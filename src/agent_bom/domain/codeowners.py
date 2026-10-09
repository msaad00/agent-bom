"""Bounded CODEOWNERS ingestion for source-finding accountability."""

from __future__ import annotations

import fnmatch
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from agent_bom.finding import Finding

_CODEOWNERS_LOCATIONS = (Path(".github/CODEOWNERS"), Path("CODEOWNERS"), Path("docs/CODEOWNERS"))


@dataclass(frozen=True)
class CodeOwnerRule:
    pattern: str
    owners: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"pattern": self.pattern, "owners": list(self.owners)}


def load_codeowners(project_root: Path) -> list[CodeOwnerRule]:
    """Load the first CODEOWNERS file in GitHub's documented search order."""
    for relative_path in _CODEOWNERS_LOCATIONS:
        candidate = project_root / relative_path
        if not candidate.is_file():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        rules: list[CodeOwnerRule] = []
        for line in lines:
            try:
                parts = shlex.split(line, comments=True, posix=True)
            except ValueError:
                continue
            if len(parts) < 2 or parts[0].startswith("!"):
                continue
            owners = tuple(owner for owner in parts[1:] if owner.startswith("@") or "@" in owner)
            if owners:
                rules.append(CodeOwnerRule(pattern=parts[0], owners=owners))
        return rules
    return []


def _rule_from_value(value: CodeOwnerRule | dict[str, object]) -> CodeOwnerRule | None:
    if isinstance(value, CodeOwnerRule):
        return value
    if not isinstance(value, dict):
        return None
    pattern = str(value.get("pattern") or value.get("path") or "").strip()
    raw_owners = value.get("owners") or value.get("owner") or []
    if isinstance(raw_owners, str):
        owners = tuple(part for part in raw_owners.replace(",", " ").split() if part)
    elif isinstance(raw_owners, (list, tuple)):
        owners = tuple(str(part).strip() for part in raw_owners if str(part).strip())
    else:
        owners = ()
    return CodeOwnerRule(pattern=pattern, owners=owners) if pattern and owners else None


def normalize_codeowners(value: object) -> list[CodeOwnerRule]:
    """Accept either ordered CODEOWNERS rules or a flattened prefix map.

    The repo-tree scan carries ownership as ``{path_prefix: owner}``, which has
    no inherent order. CODEOWNERS precedence is last-match-wins, so the prefixes
    are emitted shortest-first and the longest (most specific) prefix ends up
    last — the same "longest prefix wins" rule the ASPM overlay applies.
    """
    if isinstance(value, dict):
        ordered: list[CodeOwnerRule] = []
        for prefix in sorted(value, key=lambda item: len(str(item))):
            stripped = str(prefix).strip().strip("/")
            pattern = f"{stripped}/" if stripped else "*"
            rule = _rule_from_value({"pattern": pattern, "owners": value[prefix]})
            if rule is not None:
                ordered.append(rule)
        return ordered
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        return []
    return [rule for rule in (_rule_from_value(entry) for entry in value) if rule is not None]


def _matches(pattern: str, path: str) -> bool:
    candidate = path.replace("\\", "/").lstrip("./")
    raw_pattern = pattern.replace("\\", "/")
    anchored = raw_pattern.startswith("/")
    normalized = raw_pattern.lstrip("/")
    if normalized in {"", "*"}:
        return True
    if normalized.endswith("/"):
        prefix = normalized.rstrip("/")
        return candidate == prefix or candidate.startswith(prefix + "/")
    if "/" not in normalized:
        return fnmatch.fnmatchcase(PurePosixPath(candidate).name, normalized)
    if fnmatch.fnmatchcase(candidate, normalized) or PurePosixPath(candidate).match(normalized):
        return True
    return not anchored and PurePosixPath(candidate).match(f"**/{normalized}")


def owner_for_path(path: str, rules: object) -> CodeOwnerRule | None:
    """Return the last matching rule, matching CODEOWNERS precedence."""
    matched: CodeOwnerRule | None = None
    for rule in normalize_codeowners(rules):
        if _matches(rule.pattern, path):
            matched = rule
    return matched


def apply_codeowners(findings: Iterable[Finding], rules: object) -> None:
    """Assign source owners without replacing an explicit triage assignee."""
    materialized_rules = normalize_codeowners(rules)
    for finding in findings:
        if finding.owner:
            continue
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        path = str(finding.asset.location or evidence.get("file") or evidence.get("file_path") or "").strip()
        if not path:
            continue
        rule = owner_for_path(path, materialized_rules)
        if rule is None:
            continue
        finding.owner = ", ".join(rule.owners)
        evidence["codeowners_pattern"] = rule.pattern
        evidence["codeowners"] = list(rule.owners)
        finding.evidence = evidence


__all__ = ["CodeOwnerRule", "apply_codeowners", "load_codeowners", "normalize_codeowners", "owner_for_path"]
