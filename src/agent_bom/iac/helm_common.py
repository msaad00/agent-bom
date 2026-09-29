"""Shared helpers for the Helm chart and values scanners."""

from __future__ import annotations

import re
from typing import Any

from agent_bom.iac.models import IaCFinding

# Secret-like field name patterns for values.yaml
_SECRET_FIELD_RE = re.compile(
    r"(?:password|token|secret|key|credential|auth)",
    re.IGNORECASE,
)

# Placeholder values that should NOT be flagged
_PLACEHOLDER_VALUES = frozenset(
    {
        "",
        "changeme",
        "CHANGEME",
        "replace",
        "placeholder",
        "TODO",
    }
)

_PLACEHOLDER_PREFIX_RE = re.compile(r"^your[-_]", re.IGNORECASE)
# Helm/Jinja template expressions — resolved at deploy time, never hardcoded secrets
_TEMPLATE_VAR_RE = re.compile(r"\{\{.*?\}\}", re.DOTALL)
_SECRET_REFERENCE_FIELD_RE = re.compile(
    r"(?:^topologyKey$|LabelKey$|SecretKey$|SecretName$)",
    re.IGNORECASE,
)


def _find_line(content: str, key: str, value: Any, start_line: int = 1) -> int:
    """Best-effort line number search for a key-value pair in YAML text."""
    if isinstance(value, bool):
        val_str = "true" if value else "false"
    else:
        val_str = str(value)
    pattern = rf"{re.escape(key)}\s*:\s*{re.escape(val_str)}"
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(pattern, line):
            return i
    return start_line


def _find_key_line(content: str, key: str, start_line: int = 1) -> int:
    """Best-effort line number search for a key in YAML text."""
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(rf"\b{re.escape(key)}\s*:", line):
            return i
    return start_line


def _is_placeholder(value: str) -> bool:
    """Return True if the value is a known non-secret placeholder."""
    if value in _PLACEHOLDER_VALUES:
        return True
    if _PLACEHOLDER_PREFIX_RE.match(value):
        return True
    # Helm/Jinja template expressions ({{ .Values.* }}) are resolved at deploy time
    if _TEMPLATE_VAR_RE.search(value):
        return True
    return False


def _is_secret_reference_field(key: str) -> bool:
    """Return True for Kubernetes reference/metadata keys that are not secret material."""
    return bool(_SECRET_REFERENCE_FIELD_RE.search(key))


def _walk_secret_fields(obj: Any, content: str, file_path: str, findings: list[IaCFinding]) -> None:
    """Recursively walk a parsed YAML object and flag secret-like fields with real values."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and _SECRET_FIELD_RE.search(k) and not _is_secret_reference_field(k):
                if isinstance(v, str) and v and not _is_placeholder(v):
                    findings.append(
                        IaCFinding(
                            rule_id="HELM-003",
                            severity="critical",
                            title=f"Hardcoded secret in values.yaml: '{k}'",
                            message=(
                                f"Field '{k}' in values.yaml contains a hardcoded secret value. "
                                "Use environment variable substitution, a Secrets Store CSI driver, "
                                "or reference a Kubernetes Secret instead of hardcoding credentials."
                            ),
                            file_path=file_path,
                            line_number=_find_key_line(content, k),
                            category="helm",
                            compliance=["CIS-K8s-5.4.1", "NIST-IA-5"],
                        )
                    )
            # Recurse into nested structures regardless
            if isinstance(v, (dict, list)):
                _walk_secret_fields(v, content, file_path, findings)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _walk_secret_fields(item, content, file_path, findings)
