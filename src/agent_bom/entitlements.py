"""Local entitlement metadata for self-hosted packaging.

The entitlement contract is intentionally local and metadata-only.  It lets
operators surface support/SLA and future commercial feature metadata without
turning OSS scanner or control-plane paths into hosted-license checks.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

ENTITLEMENT_FILE_ENV = "AGENT_BOM_ENTITLEMENT_FILE"

EntitlementStatus = Literal["missing", "valid", "invalid", "expired"]

_ALLOWED_LANES = {
    "oss",
    "self-hosted-enterprise",
    "snowflake",
}


@dataclass(frozen=True)
class EntitlementCheck:
    feature: str
    enabled: bool
    status: EntitlementStatus
    reason: str
    metadata_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "enabled": self.enabled,
            "status": self.status,
            "reason": self.reason,
            "metadata_only": self.metadata_only,
        }


@dataclass(frozen=True)
class EntitlementState:
    status: EntitlementStatus
    lane: str = "oss"
    enabled_features: tuple[str, ...] = ()
    support_tier: str = "community"
    sla: str | None = None
    expires_at: str | None = None
    source: str = "default"
    errors: tuple[str, ...] = ()
    metadata_only: bool = True
    current_oss_paths_gated: bool = False
    checks: tuple[EntitlementCheck, ...] = field(default_factory=tuple)

    @property
    def valid(self) -> bool:
        return self.status == "valid"

    def check(self, feature: str) -> EntitlementCheck:
        normalized = _normalize_feature(feature)
        if self.status == "missing":
            return EntitlementCheck(
                feature=normalized,
                enabled=False,
                status=self.status,
                reason="no local entitlement metadata configured; OSS paths remain usable",
            )
        if self.status == "invalid":
            return EntitlementCheck(
                feature=normalized,
                enabled=False,
                status=self.status,
                reason="local entitlement metadata is invalid; fail-safe disables commercial metadata features only",
            )
        if self.status == "expired":
            return EntitlementCheck(
                feature=normalized,
                enabled=False,
                status=self.status,
                reason="local entitlement metadata is expired; fail-safe disables commercial metadata features only",
            )
        enabled = normalized in self.enabled_features
        return EntitlementCheck(
            feature=normalized,
            enabled=enabled,
            status=self.status,
            reason="feature listed in local entitlement metadata" if enabled else "feature not listed in local entitlement metadata",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "v1",
            "status": self.status,
            "valid": self.valid,
            "lane": self.lane,
            "enabled_features": list(self.enabled_features),
            "support": {
                "tier": self.support_tier,
                "sla": self.sla,
            },
            "expires_at": self.expires_at,
            "source": self.source,
            "errors": list(self.errors),
            "metadata_only": self.metadata_only,
            "current_oss_paths_gated": self.current_oss_paths_gated,
            "checks": [check.to_dict() for check in self.checks],
        }

    def health_summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "lane": self.lane,
            "support_tier": self.support_tier,
            "enabled_feature_count": len(self.enabled_features),
            "metadata_only": self.metadata_only,
            "current_oss_paths_gated": self.current_oss_paths_gated,
        }


def _normalize_feature(feature: str) -> str:
    return feature.strip().lower().replace("_", "-")


def _missing_state() -> EntitlementState:
    return EntitlementState(
        status="missing",
        checks=(
            EntitlementCheck(
                feature="local-entitlement-metadata",
                enabled=False,
                status="missing",
                reason="AGENT_BOM_ENTITLEMENT_FILE is not set",
            ),
        ),
    )


def _invalid_state(source: str, error: str) -> EntitlementState:
    return EntitlementState(
        status="invalid",
        source=source,
        errors=(error,),
        checks=(
            EntitlementCheck(
                feature="local-entitlement-metadata",
                enabled=False,
                status="invalid",
                reason="local entitlement metadata could not be validated",
            ),
        ),
    )


def _expired(expires_at: str) -> bool:
    try:
        parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed < datetime.now(timezone.utc)


def load_entitlement_state() -> EntitlementState:
    """Load and validate local entitlement metadata.

    Missing or invalid metadata never blocks existing OSS functionality.  The
    state is still explicit so admin/health surfaces can fail safely and tell
    operators why commercial metadata features are unavailable.
    """
    raw_path = (os.environ.get(ENTITLEMENT_FILE_ENV) or "").strip()
    if not raw_path:
        return _missing_state()

    path = Path(raw_path).expanduser()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return _invalid_state(str(path), "entitlement file is unreadable")
    except json.JSONDecodeError:
        return _invalid_state(str(path), "entitlement file is not valid JSON")

    if not isinstance(payload, dict):
        return _invalid_state(str(path), "entitlement file root must be an object")

    lane = str(payload.get("lane") or "oss").strip().lower()
    if lane not in _ALLOWED_LANES:
        return _invalid_state(str(path), f"unsupported entitlement lane: {lane}")

    raw_features = payload.get("features", [])
    if raw_features is None:
        raw_features = []
    if not isinstance(raw_features, list) or not all(isinstance(item, str) for item in raw_features):
        return _invalid_state(str(path), "features must be a list of strings")
    features = tuple(sorted({_normalize_feature(item) for item in raw_features if item.strip()}))

    support = payload.get("support") or {}
    if not isinstance(support, dict):
        return _invalid_state(str(path), "support must be an object when present")
    support_tier = str(support.get("tier") or payload.get("support_tier") or "community").strip() or "community"
    sla = support.get("sla") or payload.get("sla")
    sla_value = str(sla).strip() if sla not in (None, "") else None

    expires = payload.get("expires_at")
    expires_at = str(expires).strip() if expires not in (None, "") else None
    status: EntitlementStatus = "expired" if expires_at and _expired(expires_at) else "valid"

    state = EntitlementState(
        status=status,
        lane=lane,
        enabled_features=features,
        support_tier=support_tier,
        sla=sla_value,
        expires_at=expires_at,
        source=str(path),
    )
    return EntitlementState(
        status=state.status,
        lane=state.lane,
        enabled_features=state.enabled_features,
        support_tier=state.support_tier,
        sla=state.sla,
        expires_at=state.expires_at,
        source=state.source,
        checks=tuple(state.check(feature) for feature in features),
    )
