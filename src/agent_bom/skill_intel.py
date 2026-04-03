"""Optional threat-intel enrichment for skill bundles."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

from agent_bom.skill_bundles import SkillBundle


class ThreatIntelStatus(str, Enum):
    """Normalized threat-intel states for a bundle lookup."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    PENDING = "pending"
    UNAVAILABLE = "unavailable"


@dataclass
class ThreatIntelResult:
    """Normalized threat-intel result for one bundle."""

    provider: str
    status: ThreatIntelStatus
    source: str
    matched: bool = False
    detail: str | None = None
    reference: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the threat-intel result."""
        return {
            "provider": self.provider,
            "status": self.status.value,
            "source": self.source,
            "matched": self.matched,
            "detail": self.detail,
            "reference": self.reference,
        }


def _provider_name(document: object, source: str) -> str:
    if isinstance(document, dict):
        provider = document.get("provider")
        if isinstance(provider, str) and provider.strip():
            return provider.strip()
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return parsed.netloc
    return Path(source).name or "threat-intel"


def _load_document(source: str) -> object:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        with urlopen(source, timeout=5) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8"))
    return json.loads(Path(source).read_text(encoding="utf-8"))


def _iter_entries(document: object) -> list[dict[str, object]]:
    if isinstance(document, dict):
        for key in ("entries", "results", "items"):
            value = document.get(key)
            if isinstance(value, list):
                return [entry for entry in value if isinstance(entry, dict)]
        by_hash = document.get("entries_by_sha256")
        if isinstance(by_hash, dict):
            return [{"sha256": sha256, **entry} for sha256, entry in by_hash.items() if isinstance(entry, dict)]
    if isinstance(document, list):
        return [entry for entry in document if isinstance(entry, dict)]
    return []


def _coerce_status(raw_status: object) -> ThreatIntelStatus:
    value = str(raw_status or "").strip().lower()
    if value in {"clean", "benign", "safe", "allow"}:
        return ThreatIntelStatus.CLEAN
    if value in {"suspicious", "warn", "warning", "review"}:
        return ThreatIntelStatus.SUSPICIOUS
    if value in {"malicious", "block", "blocked"}:
        return ThreatIntelStatus.MALICIOUS
    if value in {"pending", "queued", "processing"}:
        return ThreatIntelStatus.PENDING
    return ThreatIntelStatus.UNAVAILABLE


def _match_entry(bundle: SkillBundle, entries: list[dict[str, object]]) -> dict[str, object] | None:
    file_hashes = {entry.sha256 for entry in bundle.files}
    for entry in entries:
        if entry.get("stable_id") == bundle.stable_id:
            return entry
        if entry.get("sha256") == bundle.sha256:
            return entry
        files = entry.get("files")
        if isinstance(files, list) and any(isinstance(item, dict) and item.get("sha256") in file_hashes for item in files):
            return entry
    return None


def lookup_bundle_threat_intel(bundle: SkillBundle, source: str | None) -> ThreatIntelResult | None:
    """Optionally enrich a bundle from a local or remote JSON threat-intel feed."""
    if not source:
        return None
    try:
        document = _load_document(source)
    except Exception as exc:
        return ThreatIntelResult(
            provider=_provider_name({}, source),
            status=ThreatIntelStatus.UNAVAILABLE,
            source=source,
            matched=False,
            detail=f"lookup failed: {exc}",
        )

    provider = _provider_name(document, source)
    entries = _iter_entries(document)
    match = _match_entry(bundle, entries)
    if match is None:
        return ThreatIntelResult(
            provider=provider,
            status=ThreatIntelStatus.CLEAN,
            source=source,
            matched=False,
            detail="no matching bundle hash in feed",
        )

    return ThreatIntelResult(
        provider=provider,
        status=_coerce_status(match.get("status")),
        source=source,
        matched=True,
        detail=str(match.get("detail") or match.get("reason") or "").strip() or None,
        reference=str(match.get("reference") or match.get("url") or "").strip() or None,
    )
