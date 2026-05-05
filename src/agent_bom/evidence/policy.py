"""Two-bucket evidence redaction policy.

The acceptance contract from issue #2261:

1. Every persistence path that writes evidence routes through
   :func:`redact_for_persistence`.
2. Tier A storage (audit log, compliance hub, proxy audit relay) only ever
   sees field names from :data:`TIER_A_FIELDS`. Tier B fields are dropped.
3. Tier B storage (the ``proxy_replay_log`` opt-in table) is reachable only
   when ``--capture-replay`` is set and rows carry a ``not_after`` TTL.
4. Unknown field names default to **TIER_B** — the safe choice — so newly
   added evidence keys don't accidentally promote to tier A storage.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable

# ─── Tier definition ─────────────────────────────────────────────────────────


class EvidenceTier(str, Enum):
    """Persistence tiers for evidence rows.

    Order matters: a tier ``N`` storage only accepts fields whose
    classification is ``<= N``. ``SAFE_TO_STORE`` (0) is the strictest tier;
    ``REPLAY_ONLY`` (1) accepts everything.
    """

    SAFE_TO_STORE = "safe_to_store"  # tier A — durable, exportable, audit-grade
    REPLAY_ONLY = "replay_only"  # tier B — short-TTL replay only, off by default


_TIER_RANK: dict[EvidenceTier, int] = {
    EvidenceTier.SAFE_TO_STORE: 0,
    EvidenceTier.REPLAY_ONLY: 1,
}


# ─── Field classification ────────────────────────────────────────────────────

# Conservative whitelist — every field that's safe to keep indefinitely.
# All names are lowercase; classification is case-insensitive at lookup time.
TIER_A_FIELDS: frozenset[str] = frozenset(
    {
        # Package / lockfile metadata
        "package_version",
        "package_name",
        "packages",
        "ecosystem",
        "lockfile_source",
        "purl",
        # Tool / capability metadata
        "tool_name",
        "tool",
        "scope",
        "scopes",
        "command_name",
        "event_id",
        "event_type",
        "event_timestamp",
        # Host / network identifiers
        "hostname",
        "host",
        "endpoint_host",
        # Env-var *names* only (never values)
        "env_var_name",
        "env_var",
        # Identity / agent identifiers
        "client_id",
        "agent_id",
        "agent_name",
        "source_id",
        "tenant_id",
        "session_id",
        "actor_id",
        "user_id",
        "service_account_id",
        "principal_id",
        # Timestamps and lifecycle
        "timestamp",
        "ts",
        "first_seen",
        "last_seen",
        "ingested_at",
        "not_after",
        "captured_at",
        # Status / response codes (no body)
        "status_code",
        "http_status",
        "policy",
        "policy_result",
        "decision",
        "outcome",
        "state",
        "lifecycle_state",
        "severity",
        "ttl_seconds",
        "tier",
        # W3C trace identifiers
        "trace_id",
        "span_id",
        "request_id",
        "message_id",
        "entry_id",
        "finding_id",
        "ordinal",
        "rule_id",
        "check_id",
        "reason_code",
        # Cryptographic checksums (hashes are fingerprints, not content)
        "payload_sha256",
        "record_hash",
        "prev_hash",
        "hmac_signature",
        "prev_signature",
        # Compliance metadata
        "framework",
        "applicable_frameworks",
        "applicable_frameworks_csv",
        "control_id",
        "source",
        # Quantitative scores (no PII)
        "cvss_score",
        "epss_score",
        "is_kev",
        "fixed_version",
        # Normalized structural finding fields. Free-text labels,
        # descriptions, reasons, recommendations, and remediations are
        # intentionally replay-only because scanners and runtimes often
        # populate them with copied user/workspace content.
        "id",
        "title",
        "category",
        "detector",
        "asset_type",
        "finding_type",
        "cve_id",
        "ghsa_id",
        "advisory_id",
        "rule",
        "vendor",
        "kind",
        "type",
        # Safe container keys. The values inside these containers are still
        # recursively classified, so raw args, URLs, paths, and free text are
        # dropped from tier-A even when the envelope is retained.
        "details",
        "event_relationships",
        "actor",
        "targets",
        "resources",
        "attributes",
        "normalization_version",
        "role",
        "source_field",
        # Operational audit-trail metadata. These are non-content fields:
        # counters, format / version discriminators, key-ids, nonces, time
        # ranges, expiry timestamps. Audit-log writers in api/routes/* pass
        # them via log_action() and they belong in the durable chain.
        "format",
        "version",
        "since",
        "until",
        "expires_at",
        "control_count",
        "finding_count",
        "audit_event_count",
        "batch_size",
        "class_counts",
        "source_ids",
        "nonce",
        "key_id",
        "signature_key_id",
        "method",
        "count",
        "size",
        "bytes",
        "duration_ms",
        "started_at",
        "completed_at",
        "scan_id",
        "job_id",
        "policy_id",
        "fleet_id",
        "exception_id",
        "alert_id",
    }
)

TIER_A_COUNT_MAP_FIELDS: frozenset[str] = frozenset(
    {
        "class_counts",
    }
)

# Explicit replay-only set — present so the redactor can short-circuit and
# so static auditors can see the list. Anything *not* in TIER_A_FIELDS is
# already treated as TIER_B by the conservative default; this set just makes
# the canonical tier-B shape explicit.
TIER_B_FIELDS: frozenset[str] = frozenset(
    {
        "prompt",
        "raw_prompt",
        "tool_input",
        "tool_output",
        "input",
        "output",
        "args",
        "arguments",
        "command_args",
        "argv",
        "file_path",
        "path",
        "url",
        "uri",
        "query",
        "request_body",
        "response_body",
        "body",
        "content",
        "stdout",
        "stderr",
        "user_workspace_content",
        "workspace_snippet",
        "preview",
        "screenshot",
    }
)


def classify_field(field_name: str) -> EvidenceTier:
    """Classify a field name into its persistence tier.

    Names are matched case-insensitively. Anything not on the
    :data:`TIER_A_FIELDS` whitelist is treated as :attr:`EvidenceTier.REPLAY_ONLY`
    — conservative on purpose, so a new evidence key added downstream never
    silently leaks into tier-A storage.
    """
    if not isinstance(field_name, str):
        return EvidenceTier.REPLAY_ONLY
    canonical = field_name.strip().lower()
    if canonical in TIER_A_FIELDS:
        return EvidenceTier.SAFE_TO_STORE
    return EvidenceTier.REPLAY_ONLY


# ─── Redaction ───────────────────────────────────────────────────────────────


def _is_acceptable(field_tier: EvidenceTier, target_tier: EvidenceTier) -> bool:
    return _TIER_RANK[field_tier] <= _TIER_RANK[target_tier]


def redact_for_persistence(payload: Any, target_tier: EvidenceTier) -> Any:
    """Return a copy of *payload* with fields above *target_tier* dropped.

    * For ``target_tier == SAFE_TO_STORE`` (tier A), drops every field whose
      classification is ``REPLAY_ONLY`` — i.e. everything not on the
      :data:`TIER_A_FIELDS` whitelist.
    * For ``target_tier == REPLAY_ONLY`` (tier B), keeps everything (this is
      the explicit opt-in capture path — caller must own the TTL).

    Walks dicts and lists recursively. Non-collection values are returned
    as-is. Never mutates the input.
    """
    if isinstance(payload, dict):
        out: dict[str, Any] = {}
        for key, value in payload.items():
            key_text = str(key)
            tier = classify_field(key_text)
            if not _is_acceptable(tier, target_tier):
                continue
            if target_tier is EvidenceTier.SAFE_TO_STORE and key_text.strip().lower() in TIER_A_COUNT_MAP_FIELDS:
                out[key_text] = _redact_count_map(value)
                continue
            out[key_text] = redact_for_persistence(value, target_tier)
        return out
    if isinstance(payload, list):
        return [redact_for_persistence(item, target_tier) for item in payload]
    if isinstance(payload, tuple):
        return tuple(redact_for_persistence(item, target_tier) for item in payload)
    return payload


def _redact_count_map(value: Any) -> dict[str, int | float]:
    """Preserve non-content aggregate count maps with arbitrary bucket keys."""
    if not isinstance(value, dict):
        return {}
    out: dict[str, int | float] = {}
    for key, count in value.items():
        if isinstance(count, bool) or not isinstance(count, (int, float)):
            continue
        out[str(key)[:96]] = count
    return out


# ─── Replay-only TTL helpers ────────────────────────────────────────────────

DEFAULT_REPLAY_TTL_DAYS = 7
REPLAY_TTL_ENV = "AGENT_BOM_REPLAY_TTL_DAYS"


def replay_ttl_days(default: int = DEFAULT_REPLAY_TTL_DAYS) -> int:
    """Return the configured TIER_B replay-log TTL in days.

    Reads ``AGENT_BOM_REPLAY_TTL_DAYS``. Falls back to *default* (7) if the
    env var is unset, empty, non-numeric, or non-positive.
    """
    raw = (os.environ.get(REPLAY_TTL_ENV) or "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    if parsed <= 0:
        return default
    return parsed


def replay_not_after(now: datetime | None = None, *, ttl_days: int | None = None) -> datetime:
    """Return the UTC ``not_after`` timestamp for a tier-B row written *now*.

    Both arguments are optional so callers can stay one-line:
    ``not_after=replay_not_after()``.
    """
    base = now or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    days = ttl_days if ttl_days is not None and ttl_days > 0 else replay_ttl_days()
    return base + timedelta(days=days)


# ─── UI / surface helpers ───────────────────────────────────────────────────


def tier_badge(
    tier: EvidenceTier,
    *,
    capture_replay: bool = False,
    not_after: datetime | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a small dict the dashboard renders as a per-row tier badge.

    Three rendered states match the issue's acceptance:

    * Tier A → ``Safe to store`` (durable).
    * Tier B + capture-replay enabled → ``Rotates in N days``.
    * Tier B + capture-replay disabled → ``Not persisted``.
    """
    if tier is EvidenceTier.SAFE_TO_STORE:
        return {
            "tier": tier.value,
            "label": "Safe to store",
            "icon": "lock",
            "rotates_in_days": None,
            "persisted": True,
        }
    # Tier B
    if not capture_replay:
        return {
            "tier": tier.value,
            "label": "Not persisted",
            "icon": "off",
            "rotates_in_days": None,
            "persisted": False,
        }
    rotates_in: int | None = None
    if not_after is not None:
        base = now or datetime.now(timezone.utc)
        if base.tzinfo is None:
            base = base.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        delta = not_after - base
        rotates_in = max(0, int(delta.total_seconds() // 86400))
    return {
        "tier": tier.value,
        "label": f"Rotates in {rotates_in} days" if rotates_in is not None else "Replay only",
        "icon": "hourglass",
        "rotates_in_days": rotates_in,
        "persisted": True,
    }


# ─── Convenience: classify a whole payload at once ──────────────────────────


def classify_payload(payload: dict[str, Any]) -> dict[str, EvidenceTier]:
    """Return a key→tier map for a payload — useful for tests + UI hints."""
    return {str(key): classify_field(str(key)) for key in payload.keys()}


def has_tier_b_fields(payload: dict[str, Any]) -> bool:
    """Return True when *payload* carries any field above tier A."""
    for key in payload.keys():
        if classify_field(str(key)) is EvidenceTier.REPLAY_ONLY:
            return True
    return False


def all_tier_b_field_names(payload: dict[str, Any]) -> Iterable[str]:
    for key in payload.keys():
        if classify_field(str(key)) is EvidenceTier.REPLAY_ONLY:
            yield str(key)
