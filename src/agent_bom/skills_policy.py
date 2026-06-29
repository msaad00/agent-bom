"""Policy evaluation for skill and instruction-file scan reports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from agent_bom.graph.severity import SEVERITY_THRESHOLD_LABELS, normalize_severity, severity_at_or_above

_VERDICT_ORDER = {"benign": 0, "suspicious": 1, "malicious": 2}
_REVIEW_ORDER = {"trusted": 0, "review": 1, "high_risk": 2, "blocked": 3}


class SkillsPolicyError(ValueError):
    """Raised when a skills policy file is malformed."""


@dataclass
class SkillsPolicyDecision:
    """Single warning/failure emitted by the skills policy evaluator."""

    action: str
    reason: str
    path: str
    rule_id: str | None = None
    category: str | None = None
    severity: str | None = None
    fingerprint: str | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "action": self.action,
            "reason": self.reason,
            "path": self.path,
        }
        if self.rule_id:
            data["rule_id"] = self.rule_id
        if self.category:
            data["category"] = self.category
        if self.severity:
            data["severity"] = self.severity
        if self.fingerprint:
            data["fingerprint"] = self.fingerprint
        return data


@dataclass
class SkillsPolicyResult:
    """Aggregated policy result for a skills scan."""

    status: str = "pass"
    policy_path: str | None = None
    warnings: list[SkillsPolicyDecision] = field(default_factory=list)
    violations: list[SkillsPolicyDecision] = field(default_factory=list)
    suppressions_applied: int = 0

    @property
    def failed(self) -> bool:
        return bool(self.violations)

    def add(self, decision: SkillsPolicyDecision) -> None:
        if decision.action == "fail":
            self.violations.append(decision)
            self.status = "fail"
        elif decision.action == "warn":
            self.warnings.append(decision)
            if self.status != "fail":
                self.status = "warn"

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            **({"policy_path": self.policy_path} if self.policy_path else {}),
            "warnings": [warning.to_dict() for warning in self.warnings],
            "violations": [violation.to_dict() for violation in self.violations],
            "suppressions_applied": self.suppressions_applied,
        }


def load_skills_policy(path: Path) -> dict[str, Any]:
    """Load a JSON or YAML skills policy file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SkillsPolicyError(f"could not read skills policy: {path}") from exc

    try:
        if path.suffix.lower() == ".json":
            data = json.loads(raw)
        else:
            data = yaml.safe_load(raw) or {}
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SkillsPolicyError(f"could not parse skills policy: {path}") from exc

    if not isinstance(data, dict):
        raise SkillsPolicyError("skills policy must be a JSON/YAML object")
    rules = data.get("rules", [])
    suppressions = data.get("suppressions", [])
    if rules is not None and not isinstance(rules, list):
        raise SkillsPolicyError("skills policy field 'rules' must be a list")
    if suppressions is not None and not isinstance(suppressions, list):
        raise SkillsPolicyError("skills policy field 'suppressions' must be a list")
    return data


def evaluate_skills_policy(
    report: Any,
    *,
    policy: dict[str, Any] | None = None,
    policy_path: Path | None = None,
    fail_on_verdict: str | None = None,
    warn_on_verdict: str | None = None,
    fail_on_review_verdict: str | None = None,
    warn_on_review_verdict: str | None = None,
) -> SkillsPolicyResult:
    """Evaluate warning/failure gates for a skills scan report.

    The evaluator is deterministic and explainable. ML/classifier output, when
    added later, should feed findings or confidence fields before this point
    instead of silently overriding explicit policy decisions.
    """
    policy = policy or {}
    raw_defaults = policy.get("defaults")
    defaults: dict[str, Any] = raw_defaults if isinstance(raw_defaults, dict) else {}
    result = SkillsPolicyResult(policy_path=str(policy_path) if policy_path else None)

    fail_on_verdict = fail_on_verdict or _string(defaults.get("fail_on_verdict"))
    warn_on_verdict = warn_on_verdict or _string(defaults.get("warn_on_verdict"))
    fail_on_review_verdict = fail_on_review_verdict or _string(defaults.get("fail_on_review_verdict"))
    warn_on_review_verdict = warn_on_review_verdict or _string(defaults.get("warn_on_review_verdict"))

    rules = [rule for rule in policy.get("rules", []) if isinstance(rule, dict)]
    suppressions = [entry for entry in policy.get("suppressions", []) if isinstance(entry, dict)]

    for file_report in getattr(report, "files", []):
        path = str(getattr(file_report, "path", ""))
        trust = getattr(file_report, "trust", None)
        verdict = _enum_value(getattr(trust, "verdict", None))
        review_verdict = _enum_value(getattr(trust, "review_verdict", None))
        provenance_verdict = _enum_value(getattr(trust, "provenance_verdict", None))
        content_verdict = _enum_value(getattr(trust, "content_verdict", None)) or verdict

        _apply_threshold(
            result,
            path=path,
            value=content_verdict,
            threshold=fail_on_verdict,
            order=_VERDICT_ORDER,
            action="fail",
            reason_prefix="content verdict",
        )
        _apply_threshold(
            result,
            path=path,
            value=content_verdict,
            threshold=warn_on_verdict,
            order=_VERDICT_ORDER,
            action="warn",
            reason_prefix="content verdict",
        )
        _apply_threshold(
            result,
            path=path,
            value=review_verdict,
            threshold=fail_on_review_verdict,
            order=_REVIEW_ORDER,
            action="fail",
            reason_prefix="review verdict",
        )
        _apply_threshold(
            result,
            path=path,
            value=review_verdict,
            threshold=warn_on_review_verdict,
            order=_REVIEW_ORDER,
            action="warn",
            reason_prefix="review verdict",
        )

        file_candidate = {
            "path": path,
            "verdict": verdict,
            "content_verdict": content_verdict,
            "review_verdict": review_verdict,
            "provenance_verdict": provenance_verdict,
        }
        for rule in rules:
            if _rule_matches(rule, file_candidate):
                result.add(
                    SkillsPolicyDecision(
                        action=_normalise_action(rule.get("action")),
                        reason=_rule_reason(rule, "file matched skills policy rule"),
                        path=path,
                        rule_id=_string(rule.get("id")),
                    )
                )

        audit = getattr(file_report, "audit", None)
        for finding in getattr(audit, "findings", []):
            fingerprint = _finding_fingerprint(path, finding)
            candidate = {
                **file_candidate,
                "category": getattr(finding, "category", None),
                "severity": getattr(finding, "severity", None),
                "title": getattr(finding, "title", None),
                "fingerprint": fingerprint,
            }
            if _is_suppressed(candidate, suppressions):
                result.suppressions_applied += 1
                continue
            for rule in rules:
                if not _rule_matches(rule, candidate):
                    continue
                result.add(
                    SkillsPolicyDecision(
                        action=_normalise_action(rule.get("action")),
                        reason=_rule_reason(rule, "finding matched skills policy rule"),
                        path=path,
                        rule_id=_string(rule.get("id")),
                        category=_string(candidate.get("category")),
                        severity=_string(candidate.get("severity")),
                        fingerprint=fingerprint,
                    )
                )

    return result


def _apply_threshold(
    result: SkillsPolicyResult,
    *,
    path: str,
    value: str | None,
    threshold: str | None,
    order: dict[str, int],
    action: str,
    reason_prefix: str,
) -> None:
    if not threshold or not value:
        return
    if threshold not in order:
        raise SkillsPolicyError(f"unknown {reason_prefix} threshold: {threshold}")
    if value not in order:
        return
    if order[value] >= order[threshold]:
        result.add(
            SkillsPolicyDecision(
                action=action,
                reason=f"{reason_prefix} {value} reached {action} threshold {threshold}",
                path=path,
            )
        )


def _rule_matches(rule: dict[str, Any], candidate: dict[str, Any]) -> bool:
    match = rule.get("match", rule)
    if not isinstance(match, dict):
        return False
    for key in (
        "category",
        "severity",
        "verdict",
        "content_verdict",
        "review_verdict",
        "provenance_verdict",
        "fingerprint",
    ):
        expected = match.get(key)
        if expected is not None and not _matches_value(candidate.get(key), expected):
            return False
    severity_gte = _string(match.get("severity_gte"))
    if severity_gte:
        severity = _string(candidate.get("severity"))
        if normalize_severity(severity_gte) not in SEVERITY_THRESHOLD_LABELS:
            raise SkillsPolicyError(f"unknown severity_gte threshold: {severity_gte}")
        if not severity_at_or_above(severity, severity_gte):
            return False
    path = _string(candidate.get("path")) or ""
    path_contains = _string(match.get("path_contains"))
    if path_contains and path_contains not in path:
        return False
    path_exact = _string(match.get("path"))
    if path_exact and path_exact != path:
        return False
    return True


def _matches_value(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return actual in expected
    return actual == expected


def _normalise_action(action: Any) -> str:
    value = str(action or "warn").lower().replace("block", "fail")
    if value not in {"warn", "fail"}:
        raise SkillsPolicyError(f"skills policy action must be warn, fail, or block: {action}")
    return value


def _rule_reason(rule: dict[str, Any], fallback: str) -> str:
    return _string(rule.get("reason")) or _string(rule.get("description")) or fallback


def _is_suppressed(candidate: dict[str, Any], suppressions: list[dict[str, Any]]) -> bool:
    today = datetime.now(timezone.utc).date()
    for suppression in suppressions:
        match = suppression.get("match", suppression)
        if not isinstance(match, dict):
            continue
        if _suppression_expired(suppression.get("expires"), today):
            continue
        if not suppression.get("reason") or not suppression.get("owner"):
            continue
        if _rule_matches({"match": match}, candidate):
            return True
    return False


def _suppression_expired(raw: Any, today: date) -> bool:
    if not raw:
        return True
    try:
        return date.fromisoformat(str(raw)) < today
    except ValueError:
        return True


def _finding_fingerprint(path: str, finding: Any) -> str:
    material = "|".join(
        [
            path,
            _string(getattr(finding, "category", None)) or "",
            _string(getattr(finding, "severity", None)) or "",
            _string(getattr(finding, "title", None)) or "",
            _string(getattr(finding, "detail", None)) or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _enum_value(value: Any) -> str | None:
    raw = getattr(value, "value", value)
    return _string(raw)


def _string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
