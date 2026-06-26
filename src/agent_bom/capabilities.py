"""Capability registry — the nothing-silent surface for gated features.

agent-bom unlocks deeper coverage on *stated* conditions: an opt-in env var, a
credential, a scoped cloud role, a prior scan, or data already present locally.
For a security tool, a silently-skipped capability is the worst failure mode: a
gap that looks like coverage. A disabled or degraded capability must therefore
**announce itself** and say exactly how to turn it on.

This module is that announcement. It declares every gated capability once, with:

* what it does,
* the unlock CONDITION (env var / credential / scoped role / prior scan / data),
* the current STATE — ``on`` / ``off`` / ``degraded`` — *computed* from the
  environment, never assumed, and
* a one-line HOW-TO-UNLOCK string.

The ``agent-bom doctor`` / ``agent-bom capabilities`` command renders this list.
:func:`scan_status_line` exposes a single line the scan path can print at start
("running with X enabled; Y available — set Z").

Hard rules this module keeps:

* **Nothing-silent.** Every gated feature lives here. A test asserts each known
  gate appears with a state and an unlock path.
* **No secrets.** Probing only ever reports *presence/absence* of a variable and
  the variable *name* — never the value. ``GOOGLE_APPLICATION_CREDENTIALS`` is a
  path, but even that is not printed; only "set / not set".
* **Deterministic + graceful.** Probing reads the environment and the local
  filesystem only, never the network, and is wrapped so a probe can never crash
  the command — a failed probe degrades to ``unknown`` rather than raising.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Literal

# Shared truthy vocabulary — matches every gate in the codebase (side-scan,
# audit-trail, the inventory flags, registry airgap). Kept here so the registry
# probes a gate the same way the gated module does.
_TRUTHY = {"1", "true", "yes", "on"}


def env_truthy(name: str) -> bool:
    """True when ``name`` is set to a recognized truthy value.

    Mirrors the parsing used by the gated modules (``is_sidescan_enabled``,
    ``config._bool``, the inventory gates) so ``doctor`` never disagrees with the
    feature it describes.
    """
    raw = os.environ.get(name)
    if raw is None:
        return False
    return raw.strip().lower() in _TRUTHY


def env_present(name: str) -> bool:
    """True when ``name`` is set to any non-empty value (presence only).

    Used for credential-style variables where the *value* gates behavior but must
    never be inspected or printed — only its presence is reported.
    """
    return bool(os.environ.get(name, "").strip())


class State(str, Enum):
    """Computed state of a capability in the current environment."""

    ON = "on"
    """Unlock condition met — the capability runs."""

    OFF = "off"
    """Available but not unlocked — the unlock path tells the operator how."""

    DEGRADED = "degraded"
    """Partially active: it runs, but with reduced coverage or a caveat."""

    UNKNOWN = "unknown"
    """A probe failed to evaluate cleanly — never silent, surfaced as unknown."""


# Group buckets used by ``doctor`` to order the output as a coverage story.
Group = Literal["cloud", "scan", "runtime", "data"]


@dataclass(frozen=True)
class CapabilityStatus:
    """The resolved status of one capability for the current environment."""

    state: State
    detail: str
    """Why the capability is in this state — never contains a secret value."""


# A probe returns the live status. It must be pure w.r.t. the process env +
# local filesystem, must not hit the network, and must not raise (the registry
# wraps it defensively, but probes are expected to handle their own errors).
Probe = Callable[[], CapabilityStatus]


@dataclass(frozen=True)
class Capability:
    """A declaratively-gated capability and how to unlock it.

    Attributes:
        key: Stable identifier (used in tests and machine output).
        name: Human title.
        group: Coverage bucket for grouped rendering.
        does: One sentence on what the capability adds.
        condition: Human description of the unlock CONDITION (env var, credential,
            scoped role, prior scan, or data present).
        unlock: Copy-pasteable one-liner that flips the capability on.
        env_vars: Variable names this capability reads. Only *names* are ever
            shown; values are never read for display.
        probe: Computes the live :class:`CapabilityStatus` from the environment.
    """

    key: str
    name: str
    group: Group
    does: str
    condition: str
    unlock: str
    env_vars: tuple[str, ...]
    probe: Probe = field(repr=False)

    def status(self) -> CapabilityStatus:
        """Evaluate the live state, degrading to ``unknown`` if the probe fails.

        Graceful by contract: a buggy or environment-sensitive probe surfaces as
        ``UNKNOWN`` (still visible, still with an unlock path) rather than
        crashing ``doctor`` — a silent capability is never acceptable.
        """
        try:
            return self.probe()
        except Exception as exc:  # noqa: BLE001 — never let a probe crash doctor
            return CapabilityStatus(State.UNKNOWN, f"probe error: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Probe builders for the common gate shapes
# ---------------------------------------------------------------------------


def _env_flag_probe(env_var: str, on_detail: str, off_detail: str) -> Probe:
    """Probe a simple truthy env-flag gate (side-scan, audit-trail, inventory)."""

    def probe() -> CapabilityStatus:
        if env_truthy(env_var):
            return CapabilityStatus(State.ON, on_detail)
        return CapabilityStatus(State.OFF, off_detail)

    return probe


def _inventory_probe(inventory_var: str, cred_vars: tuple[str, ...], provider: str) -> Probe:
    """Probe a cloud-inventory gate: opt-in flag plus credential presence.

    Three honest states:
      * flag off            → OFF (nothing is collected; this is the default).
      * flag on, no creds   → DEGRADED (opted in, but the next scan reads nothing).
      * flag on, creds set  → ON.
    """

    def probe() -> CapabilityStatus:
        if not env_truthy(inventory_var):
            return CapabilityStatus(State.OFF, f"{inventory_var} not set — {provider} inventory off (default)")
        detected = [name for name in cred_vars if env_present(name)]
        if detected:
            return CapabilityStatus(State.ON, f"{inventory_var} set; credentials detected ({', '.join(detected)})")
        expected = ", ".join(cred_vars)
        return CapabilityStatus(
            State.DEGRADED,
            f"{inventory_var} set but no credentials detected — set one of: {expected}",
        )

    return probe


def _scan_cache_db_path() -> Path:
    """Resolve the local vuln-cache path the same way ``ScanCache`` does."""
    override = os.environ.get("AGENT_BOM_SCAN_CACHE")
    if override and override.strip():
        return Path(override)
    return Path.home() / ".agent-bom" / "scan_cache.db"


def _vuln_cache_probe() -> CapabilityStatus:
    """Probe the local vuln-DB cache: data-present + freshness gate.

    States:
      * no cache file               → OFF (live OSV/GHSA/NVD; first scan creates it).
      * cache present but stale     → DEGRADED (recent CVEs may be missed).
      * cache present and fresh     → ON.
    Offline mode is surfaced as a caveat so an airgapped run is never silent.
    """
    offline = env_truthy("AGENT_BOM_VULN_DB_OFFLINE")
    db_path = _scan_cache_db_path()
    if not db_path.exists():
        base = "no local cache yet — scanning runs live (OSV/GHSA/NVD); first scan populates it"
        if offline:
            return CapabilityStatus(State.DEGRADED, "offline forced but no local cache — coverage will be empty")
        return CapabilityStatus(State.OFF, base)

    try:
        from agent_bom.vuln_freshness import max_age_hours

        threshold = max_age_hours()
    except Exception:
        threshold = 24

    age_hours: float | None = None
    try:
        import time

        age_hours = max(0.0, (time.time() - db_path.stat().st_mtime) / 3600.0)
    except OSError:
        age_hours = None

    suffix = " (offline mode)" if offline else ""
    if age_hours is None:
        return CapabilityStatus(State.ON, f"local cache present at {db_path.name}{suffix}")
    if age_hours > threshold:
        return CapabilityStatus(
            State.DEGRADED,
            f"local cache is ~{age_hours:.0f}h old (> {threshold}h) — recent CVEs may be missed; "
            f"refresh with `agent-bom db update`{suffix}",
        )
    return CapabilityStatus(State.ON, f"local cache fresh (~{age_hours:.0f}h old, threshold {threshold}h){suffix}")


def _registry_sweep_probe() -> CapabilityStatus:
    """Probe the container-registry sweep: credentials gate + airgap caveat."""
    airgapped = env_truthy("AGENT_BOM_REGISTRY_AIRGAPPED")
    has_creds = env_present("AGENT_BOM_REGISTRY_USER") and env_present("AGENT_BOM_REGISTRY_PASS")
    if airgapped:
        return CapabilityStatus(
            State.DEGRADED,
            "AGENT_BOM_REGISTRY_AIRGAPPED set — sweep stays within the airgap (no external registry pulls)",
        )
    if has_creds:
        return CapabilityStatus(State.ON, "registry credentials detected (AGENT_BOM_REGISTRY_USER/PASS)")
    return CapabilityStatus(
        State.OFF,
        "no registry credentials — anonymous/public pulls only; set AGENT_BOM_REGISTRY_USER + AGENT_BOM_REGISTRY_PASS for private images",
    )


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

# Per-cloud inventory credential vars (mirrors cli/_entry_points.py connect map).
_AWS_CRED_VARS = ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE")
_AZURE_CRED_VARS = ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID")
_GCP_CRED_VARS = ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT")
_SNOWFLAKE_CRED_VARS = ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PRIVATE_KEY_PATH")


def _build_registry() -> tuple[Capability, ...]:
    """Construct the immutable capability list.

    A function (not a module-level literal) so the probe closures are built once
    and the result can be wrapped in a tuple for immutability.
    """
    caps: list[Capability] = [
        # ---- Cloud inventory (opt-in flag + scoped read-only role) ------------
        Capability(
            key="aws_inventory",
            name="AWS cloud inventory",
            group="cloud",
            does="Folds the AWS estate (resources, IAM, exposure) into the graph.",
            condition="opt-in env var AGENT_BOM_AWS_INVENTORY + AWS read-only credentials",
            unlock="export AGENT_BOM_AWS_INVENTORY=1  (role: SecurityAudit + ViewOnlyAccess)",
            env_vars=("AGENT_BOM_AWS_INVENTORY", *_AWS_CRED_VARS),
            probe=_inventory_probe("AGENT_BOM_AWS_INVENTORY", _AWS_CRED_VARS, "AWS"),
        ),
        Capability(
            key="azure_inventory",
            name="Azure cloud inventory",
            group="cloud",
            does="Folds the Azure estate into the graph (read-only Reader role).",
            condition="opt-in env var AGENT_BOM_AZURE_INVENTORY + Azure credentials",
            unlock="export AGENT_BOM_AZURE_INVENTORY=1  (role: built-in Reader)",
            env_vars=("AGENT_BOM_AZURE_INVENTORY", *_AZURE_CRED_VARS),
            probe=_inventory_probe("AGENT_BOM_AZURE_INVENTORY", _AZURE_CRED_VARS, "Azure"),
        ),
        Capability(
            key="gcp_inventory",
            name="GCP cloud inventory",
            group="cloud",
            does="Folds the GCP estate into the graph (read-only viewer role).",
            condition="opt-in env var AGENT_BOM_GCP_INVENTORY + GCP credentials",
            unlock="export AGENT_BOM_GCP_INVENTORY=1  (role: roles/viewer + securityReviewer)",
            env_vars=("AGENT_BOM_GCP_INVENTORY", *_GCP_CRED_VARS),
            probe=_inventory_probe("AGENT_BOM_GCP_INVENTORY", _GCP_CRED_VARS, "GCP"),
        ),
        Capability(
            key="snowflake_inventory",
            name="Snowflake inventory",
            group="cloud",
            does="Folds the Snowflake estate (data stores, grants) into the graph.",
            condition="opt-in env var AGENT_BOM_SNOWFLAKE_INVENTORY + Snowflake credentials",
            unlock="export AGENT_BOM_SNOWFLAKE_INVENTORY=1  (read-only governance role)",
            env_vars=("AGENT_BOM_SNOWFLAKE_INVENTORY", *_SNOWFLAKE_CRED_VARS),
            probe=_inventory_probe("AGENT_BOM_SNOWFLAKE_INVENTORY", _SNOWFLAKE_CRED_VARS, "Snowflake"),
        ),
        # ---- Cloud organization roll-up ---------------------------------------
        Capability(
            key="org_rollup",
            name="Cloud organization roll-up",
            group="cloud",
            does="Enumerates the whole org (AWS OUs/SCPs, GCP/Snowflake org accounts).",
            condition="opt-in env var AGENT_BOM_CLOUD_INVENTORY + org-level read role",
            unlock="export AGENT_BOM_CLOUD_INVENTORY=1  (needs org-admin read scope, e.g. ORGADMIN)",
            env_vars=("AGENT_BOM_CLOUD_INVENTORY",),
            probe=_env_flag_probe(
                "AGENT_BOM_CLOUD_INVENTORY",
                "AGENT_BOM_CLOUD_INVENTORY set — organization roll-up enabled",
                "AGENT_BOM_CLOUD_INVENTORY not set — single account only (org roll-up off)",
            ),
        ),
        # ---- Side-scan (the one opt-in non-read-only capability) --------------
        Capability(
            key="side_scan",
            name="AWS agentless side-scan (CWPP)",
            group="cloud",
            does="Snapshots EBS volumes in-account to read the filesystem SBOM + secret types.",
            condition="opt-in env var AGENT_BOM_SIDESCAN (the one non-read-only capability)",
            unlock="export AGENT_BOM_SIDESCAN=1  (needs a separately-scoped snapshot role)",
            env_vars=("AGENT_BOM_SIDESCAN",),
            probe=_env_flag_probe(
                "AGENT_BOM_SIDESCAN",
                "AGENT_BOM_SIDESCAN set — agentless side-scan enabled (in-account, metadata-only)",
                "AGENT_BOM_SIDESCAN not set — side-scan off (default; everything else is read-only)",
            ),
        ),
        # ---- Cloud audit-trail ------------------------------------------------
        Capability(
            key="audit_trail",
            name="Cloud audit-trail correlation",
            group="cloud",
            does="Pulls a bounded slice of cloud audit logs to draw who-did-what reach edges.",
            condition="opt-in env var AGENT_BOM_AUDIT_TRAIL + cloud read credentials",
            unlock="export AGENT_BOM_AUDIT_TRAIL=1",
            env_vars=("AGENT_BOM_AUDIT_TRAIL",),
            probe=_env_flag_probe(
                "AGENT_BOM_AUDIT_TRAIL",
                "AGENT_BOM_AUDIT_TRAIL set — audit-trail correlation enabled",
                "AGENT_BOM_AUDIT_TRAIL not set — audit-trail correlation off (default)",
            ),
        ),
        # ---- Registry sweep ---------------------------------------------------
        Capability(
            key="registry_sweep",
            name="Container-registry sweep",
            group="scan",
            does="Sweeps a container registry's images/tags for vulnerable packages.",
            condition="registry credentials present (private images); airgap flag respected",
            unlock="export AGENT_BOM_REGISTRY_USER=... AGENT_BOM_REGISTRY_PASS=...",
            env_vars=("AGENT_BOM_REGISTRY_USER", "AGENT_BOM_REGISTRY_PASS", "AGENT_BOM_REGISTRY_AIRGAPPED"),
            probe=_registry_sweep_probe,
        ),
        # ---- Vuln-DB cache + freshness (data present) ------------------------
        Capability(
            key="vuln_db_cache",
            name="Local vuln-DB cache",
            group="data",
            does="Serves CVE matches from a local cache for fast, offline-capable scans.",
            condition="data present: a populated local cache; freshness within threshold",
            unlock="run a scan to populate it, or `agent-bom db update` to refresh",
            env_vars=("AGENT_BOM_SCAN_CACHE", "AGENT_BOM_VULN_DB_MAX_AGE_HOURS", "AGENT_BOM_VULN_DB_OFFLINE"),
            probe=_vuln_cache_probe,
        ),
    ]
    return tuple(caps)


CAPABILITIES: tuple[Capability, ...] = _build_registry()

# Stable group order for rendering — a coverage story, cloud-first.
GROUP_ORDER: tuple[Group, ...] = ("cloud", "scan", "runtime", "data")
GROUP_TITLES: dict[Group, str] = {
    "cloud": "Cloud coverage",
    "scan": "Scan coverage",
    "runtime": "Runtime coverage",
    "data": "Vulnerability data",
}


def capability_by_key(key: str) -> Capability | None:
    """Return the capability with ``key``, or ``None``."""
    for cap in CAPABILITIES:
        if cap.key == key:
            return cap
    return None


def resolved_capabilities() -> list[tuple[Capability, CapabilityStatus]]:
    """Evaluate every capability against the current environment.

    Deterministic for a fixed environment + filesystem; never hits the network;
    never raises (each probe is wrapped). The ordering matches ``CAPABILITIES``.
    """
    return [(cap, cap.status()) for cap in CAPABILITIES]


def coverage_summary() -> dict[State, int]:
    """Count capabilities by state for the one-line coverage summary."""
    counts: dict[State, int] = {state: 0 for state in State}
    for _cap, status in resolved_capabilities():
        counts[status.state] += 1
    return counts


def coverage_line() -> str:
    """A single deterministic coverage sentence safe to print anywhere."""
    counts = coverage_summary()
    total = len(CAPABILITIES)
    parts = [f"{counts[State.ON]} enabled", f"{counts[State.OFF]} available to unlock"]
    if counts[State.DEGRADED]:
        parts.append(f"{counts[State.DEGRADED]} degraded")
    if counts[State.UNKNOWN]:
        parts.append(f"{counts[State.UNKNOWN]} unknown")
    return f"Coverage: {', '.join(parts)} (of {total} gated capabilities)."


def scan_status_line() -> str:
    """One line for the scan path: what's running, and the top thing to unlock.

    Names no secret values. Reusable by the scan start so a skipped capability is
    announced rather than silently absent. Example::

        Running with 2 capabilities enabled; 6 available — e.g. set
        AGENT_BOM_AWS_INVENTORY (AWS cloud inventory). Run `agent-bom doctor`.
    """
    resolved = resolved_capabilities()
    enabled = [cap for cap, st in resolved if st.state is State.ON]
    degraded = [cap for cap, st in resolved if st.state is State.DEGRADED]
    off = [cap for cap, st in resolved if st.state is State.OFF]

    head = f"Running with {len(enabled)} capabilit{'y' if len(enabled) == 1 else 'ies'} enabled"
    bits = [head]
    if degraded:
        bits.append(f"{len(degraded)} degraded ({degraded[0].name})")
    if off:
        first = off[0]
        primary_var = first.env_vars[0] if first.env_vars else ""
        hint = f" — e.g. set {primary_var} ({first.name})" if primary_var else ""
        bits.append(f"{len(off)} available{hint}")
    return "; ".join(bits) + ". Run `agent-bom doctor` for the full list."


__all__ = [
    "CAPABILITIES",
    "GROUP_ORDER",
    "GROUP_TITLES",
    "Capability",
    "CapabilityStatus",
    "Group",
    "State",
    "capability_by_key",
    "coverage_line",
    "coverage_summary",
    "env_present",
    "env_truthy",
    "resolved_capabilities",
    "scan_status_line",
]
