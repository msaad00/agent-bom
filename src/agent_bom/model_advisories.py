"""AI model advisory and model-card risk feed support.

This module intentionally keeps model-specific intelligence separate from
package CVE/OSV advisory matching.  Model-card signals and curated feed rules
become model supply-chain evidence; they do not overwrite conventional
dependency findings.
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path
from typing import Any

_DEFAULT_FEED = "ai_model_advisories.json"
_FEED_ENV = "AGENT_BOM_AI_MODEL_ADVISORY_FEED"


@dataclass(frozen=True)
class ModelAdvisory:
    advisory_id: str
    registry: str
    model_id_pattern: str
    risk_type: str
    severity: str
    confidence: str
    summary: str
    evidence_url: str
    source: str
    freshness: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": 1, "entries": [], "source": str(path), "freshness": "unavailable"}
    return data if isinstance(data, dict) else {"schema_version": 1, "entries": [], "source": str(path), "freshness": "invalid"}


def load_model_advisory_feed(path: str | Path | None = None) -> dict[str, Any]:
    """Load a model advisory feed from an explicit path, env var, or bundle."""

    selected = path or os.environ.get(_FEED_ENV)
    if selected:
        return _load_json(Path(selected))
    try:
        with resources.files("agent_bom.data").joinpath(_DEFAULT_FEED).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"schema_version": 1, "entries": [], "source": "bundled", "freshness": "unavailable"}
    return data if isinstance(data, dict) else {"schema_version": 1, "entries": [], "source": "bundled", "freshness": "invalid"}


def feed_posture(feed: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return non-secret freshness/degraded-mode posture for the advisory feed."""

    payload = feed or load_model_advisory_feed()
    entries = payload.get("entries")
    entry_count = len(entries) if isinstance(entries, list) else 0
    freshness = str(payload.get("freshness") or "unknown")
    status = "available" if entry_count else "degraded"
    if freshness in {"unavailable", "invalid"}:
        status = "degraded"
    return {
        "schema_version": int(payload.get("schema_version") or 1),
        "status": status,
        "source": str(payload.get("source") or "bundled"),
        "freshness": freshness,
        "entry_count": entry_count,
        "last_updated": payload.get("last_updated"),
    }


def _entry_matches(entry: dict[str, Any], *, registry: str, model_id: str, tags: set[str], card_data: dict[str, Any]) -> bool:
    if str(entry.get("registry") or "").lower() not in {registry.lower(), "*"}:
        return False
    pattern = str(entry.get("model_id_pattern") or "*")
    if not fnmatch.fnmatchcase(model_id.lower(), pattern.lower()):
        return False
    match = entry.get("match")
    if not isinstance(match, dict) or not match:
        return True
    tag = match.get("tag")
    if isinstance(tag, str) and tag not in tags:
        return False
    card_field = match.get("card_field")
    if isinstance(card_field, str) and card_field not in card_data:
        return False
    return True


def match_model_advisories(
    model_id: str,
    *,
    registry: str = "huggingface",
    tags: list[str] | None = None,
    card_data: dict[str, Any] | None = None,
    feed: dict[str, Any] | None = None,
) -> list[ModelAdvisory]:
    """Match model-specific advisory rules without touching package CVEs."""

    payload = feed or load_model_advisory_feed()
    tag_set = {str(tag) for tag in (tags or [])}
    card = card_data or {}
    advisories: list[ModelAdvisory] = []
    for raw in payload.get("entries", []):
        if not isinstance(raw, dict):
            continue
        if not _entry_matches(raw, registry=registry, model_id=model_id, tags=tag_set, card_data=card):
            continue
        advisories.append(
            ModelAdvisory(
                advisory_id=str(raw.get("id") or raw.get("advisory_id") or "AI-MODEL-ADVISORY"),
                registry=str(raw.get("registry") or registry),
                model_id_pattern=str(raw.get("model_id_pattern") or "*"),
                risk_type=str(raw.get("risk_type") or "model_card_risk"),
                severity=str(raw.get("severity") or "medium").lower(),
                confidence=str(raw.get("confidence") or "medium").lower(),
                summary=str(raw.get("summary") or ""),
                evidence_url=str(raw.get("evidence_url") or ""),
                source=str(raw.get("source") or payload.get("source") or "model_advisory_feed"),
                freshness=str(raw.get("freshness") or payload.get("freshness") or "unknown"),
            )
        )
    return advisories


def model_advisories_to_dict(advisories: list[ModelAdvisory]) -> list[dict[str, str]]:
    return [advisory.to_dict() for advisory in advisories]
