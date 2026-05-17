"""dbt project security scanner.

Scans dbt projects for common credential, transport, package provenance, SQL
injection, hook, and CI/CD hygiene issues.  The scanner is static, local-only,
and intentionally conservative: it reports concrete configuration or source
patterns without executing dbt or connecting to warehouses.

Rules
-----
DBT-SEC-001  profiles.yml contains hardcoded credential material
DBT-SEC-002  profiles.yml contains connection string with embedded password
DBT-SEC-003  profiles.yml disables SSL/TLS
DBT-SEC-004  profiles.yml uses password authentication
DBT-SEC-005  dbt_project.yml clean-targets points outside project
DBT-SEC-006  dbt_project.yml has unsafe dispatch namespace search order
DBT-SEC-007  dbt_project.yml missing require-dbt-version
DBT-SEC-008  packages.yml has unpinned package reference
DBT-SEC-009  private git package lacks pinned revision
DBT-SEC-010  package source uses untrusted git transport
DBT-SEC-011  SQL uses var() directly in raw SQL
DBT-SEC-012  run_query() uses user-controlled input
DBT-SEC-013  post-hook grants ALL privileges
DBT-SEC-014  log() may expose sensitive data
DBT-SEC-015  env_var() references secret-like values in SQL
DBT-SEC-016  CI runs dbt without --fail-fast
DBT-SEC-017  CI runs dbt without a matching dbt test step
DBT-SEC-018  dbt seed data appears to contain sensitive columns
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml  # type: ignore[import-untyped]

from agent_bom.iac.models import IaCFinding, IaCResourceType

_DBT_PROJECT_NAMES = frozenset({"dbt_project.yml", "dbt_project.yaml"})
_DBT_PROFILE_NAMES = frozenset({"profiles.yml", "profiles.yaml"})
_DBT_PACKAGE_NAMES = frozenset({"packages.yml", "packages.yaml"})
_CI_WORKFLOW_PARTS = (".github", "workflows")
_SECRET_KEY_RE = re.compile(r"(?:password|token|private[_-]?key|secret|credential|api[_-]?key)", re.IGNORECASE)
_CONNECTION_WITH_PASSWORD_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s@/]+@", re.IGNORECASE)
_REQUIRE_SSL_FALSE_RE = re.compile(r"\brequire_ssl\s*:\s*false\b|\bsslmode\s*:\s*(?:disable|allow)\b", re.IGNORECASE)
_PASSWORD_AUTH_RE = re.compile(r"\b(?:method|auth(?:entication)?)\s*:\s*password\b|\bpassword\s*:", re.IGNORECASE)
_VAR_RAW_SQL_RE = re.compile(r"(?<!['\"])\{\{\s*var\([^}]+?\)\s*\}\}(?!['\"])", re.IGNORECASE)
_RUN_QUERY_INPUT_RE = re.compile(r"run_query\s*\([^)]*(?:var\(|env_var\()", re.IGNORECASE | re.DOTALL)
_GRANT_ALL_RE = re.compile(r"\bGRANT\s+ALL\b", re.IGNORECASE)
_POST_HOOK_RE = re.compile(r"post-hook|post_hook|\+post-hook|\+post_hook", re.IGNORECASE)
_LOG_SECRET_RE = re.compile(r"log\s*\([^)]*(?:env_var\(|password|token|secret|private[_-]?key)", re.IGNORECASE | re.DOTALL)
_ENV_SECRET_RE = re.compile(
    r"env_var\s*\(\s*['\"]([^'\"]*(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY|API_KEY|CREDENTIAL)[^'\"]*)['\"]", re.IGNORECASE
)
_DBT_RUN_RE = re.compile(r"\bdbt\s+run\b", re.IGNORECASE)
_DBT_TEST_RE = re.compile(r"\bdbt\s+test\b", re.IGNORECASE)
_SENSITIVE_SEED_HEADER_RE = re.compile(
    r"\b(?:ssn|social_security|dob|date_of_birth|email|phone|address|credit_card|card_number)\b", re.IGNORECASE
)
_PINNED_VERSION_RE = re.compile(r"^(?:v?\d+\.\d+(?:\.\d+)?(?:[-+][a-zA-Z0-9_.-]+)?|[a-f0-9]{12,40})$")


def _finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    message: str,
    path: Path,
    line: int,
    remediation: str,
    compliance: list[str] | None = None,
) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=str(path),
        line_number=max(1, line),
        category="dbt",
        compliance=compliance or ["NIST-CSF-PR.DS-5", "SOC2-CC6.1"],
        remediation=remediation,
        resource_type=IaCResourceType.DBT_PROJECT,
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_yaml(path: Path) -> Any:
    text = _read_text(path)
    if not text:
        return {}
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return {}


def _line_for_pattern(content: str, pattern: re.Pattern[str], default: int = 1) -> int:
    match = pattern.search(content)
    if not match:
        return default
    return content.count("\n", 0, match.start()) + 1


def _line_for_key(content: str, key: str) -> int:
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*:", re.MULTILINE)
    return _line_for_pattern(content, key_re)


def _iter_values(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        items: list[tuple[tuple[str, ...], Any]] = []
        for key, child in value.items():
            items.extend(_iter_values(child, (*path, str(key))))
        return items
    if isinstance(value, list):
        items = []
        for index, child in enumerate(value):
            items.extend(_iter_values(child, (*path, str(index))))
        return items
    return [(path, value)]


def _scan_profiles(path: Path) -> list[IaCFinding]:
    content = _read_text(path)
    data = _load_yaml(path)
    findings: list[IaCFinding] = []

    if _CONNECTION_WITH_PASSWORD_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-002",
                severity="high",
                title="Connection string embeds credentials",
                message="profiles.yml contains a URI with username and password material in the authority section.",
                path=path,
                line=_line_for_pattern(content, _CONNECTION_WITH_PASSWORD_RE),
                remediation=(
                    "Use environment variables, key-pair auth, OAuth, or a secret manager reference instead of embedded URI credentials."
                ),
            )
        )

    for key_path, value in _iter_values(data):
        key_name = key_path[-1] if key_path else ""
        if _SECRET_KEY_RE.search(key_name) and isinstance(value, str) and value.strip() and "{{" not in value:
            findings.append(
                _finding(
                    rule_id="DBT-SEC-001",
                    severity="high",
                    title="Hardcoded dbt credential",
                    message=f"profiles.yml contains a literal value for secret-like key '{key_name}'.",
                    path=path,
                    line=_line_for_key(content, key_name),
                    remediation="Replace literal credentials with env_var(), key-pair auth, OAuth, or a warehouse-native secret reference.",
                )
            )
        if key_name.lower() in {"require_ssl", "sslmode"}:
            value_text = str(value).strip().lower()
            if value is False or value_text in {"false", "disable", "allow"}:
                findings.append(
                    _finding(
                        rule_id="DBT-SEC-003",
                        severity="medium",
                        title="dbt profile disables SSL/TLS",
                        message=(
                            f"profiles.yml sets {key_name} to {value!r}, which can permit unencrypted or weakly verified "
                            "warehouse connections."
                        ),
                        path=path,
                        line=_line_for_key(content, key_name),
                        remediation=(
                            "Require TLS for warehouse connections and prefer certificate verification where the adapter supports it."
                        ),
                    )
                )

    if _REQUIRE_SSL_FALSE_RE.search(content) and not any(f.rule_id == "DBT-SEC-003" for f in findings):
        findings.append(
            _finding(
                rule_id="DBT-SEC-003",
                severity="medium",
                title="dbt profile disables SSL/TLS",
                message="profiles.yml disables SSL/TLS or sets a weak sslmode.",
                path=path,
                line=_line_for_pattern(content, _REQUIRE_SSL_FALSE_RE),
                remediation="Require TLS for warehouse connections and prefer certificate verification where the adapter supports it.",
            )
        )

    if _PASSWORD_AUTH_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-004",
                severity="medium",
                title="dbt profile uses password authentication",
                message=(
                    "Password authentication is configured for a dbt profile. Key-pair, OAuth, or workload identity usually gives "
                    "better rotation and audit behavior."
                ),
                path=path,
                line=_line_for_pattern(content, _PASSWORD_AUTH_RE),
                remediation="Prefer key-pair, OAuth, or cloud workload identity for production profiles.",
            )
        )

    return findings


def _scan_dbt_project(path: Path) -> list[IaCFinding]:
    content = _read_text(path)
    data = _load_yaml(path)
    findings: list[IaCFinding] = []

    if isinstance(data, dict) and not data.get("require-dbt-version"):
        findings.append(
            _finding(
                rule_id="DBT-SEC-007",
                severity="medium",
                title="dbt project does not pin supported dbt versions",
                message="dbt_project.yml is missing require-dbt-version, so CI may run with an unintended dbt-core version.",
                path=path,
                line=1,
                remediation="Add require-dbt-version with a bounded compatible range, for example ['>=1.7.0', '<2.0.0'].",
                compliance=["SLSA-Build-L2", "NIST-CSF-PR.IP-1"],
            )
        )

    clean_targets = data.get("clean-targets", []) if isinstance(data, dict) else []
    if isinstance(clean_targets, list):
        for target in clean_targets:
            target_text = str(target)
            if target_text.startswith("../") or target_text == ".." or "/.." in target_text:
                findings.append(
                    _finding(
                        rule_id="DBT-SEC-005",
                        severity="high",
                        title="dbt clean-targets points outside the project",
                        message=f"clean-targets includes {target_text!r}, which can delete files outside the dbt project during dbt clean.",
                        path=path,
                        line=_line_for_key(content, "clean-targets"),
                        remediation=(
                            "Keep clean-targets scoped to generated directories inside the project, such as target and dbt_packages."
                        ),
                    )
                )

    dispatch = data.get("dispatch", []) if isinstance(data, dict) else []
    if isinstance(dispatch, list):
        for entry in dispatch:
            if not isinstance(entry, dict):
                continue
            search_order = entry.get("search_order", [])
            if isinstance(search_order, list) and search_order and str(search_order[0]) not in {"dbt", entry.get("macro_namespace")}:
                findings.append(
                    _finding(
                        rule_id="DBT-SEC-006",
                        severity="medium",
                        title="dbt dispatch search order prioritizes third-party macros",
                        message=(
                            "dispatch.search_order places a package before dbt or the declared macro namespace, which can shadow "
                            "built-in macros."
                        ),
                        path=path,
                        line=_line_for_key(content, "dispatch"),
                        remediation="Review dispatch search order and keep trusted namespaces first.",
                    )
                )

    if _POST_HOOK_RE.search(content) and _GRANT_ALL_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-013",
                severity="high",
                title="dbt post-hook grants ALL privileges",
                message="A dbt post-hook contains GRANT ALL, which can over-broaden data warehouse privileges.",
                path=path,
                line=_line_for_pattern(content, _GRANT_ALL_RE),
                remediation="Grant the minimum required privileges to a specific role and avoid broad ALL grants in dbt hooks.",
            )
        )

    return findings


def _is_pinned_revision(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    return bool(_PINNED_VERSION_RE.match(normalized)) and normalized.lower() not in {"main", "master", "latest", "head"}


def _scan_packages(path: Path) -> list[IaCFinding]:
    content = _read_text(path)
    data = _load_yaml(path)
    packages = data.get("packages", []) if isinstance(data, dict) else []
    findings: list[IaCFinding] = []
    if not isinstance(packages, list):
        return findings

    for package in packages:
        if not isinstance(package, dict):
            continue
        package_label = str(package.get("package") or package.get("git") or package.get("local") or "package")
        version = package.get("version") or package.get("revision")
        git = str(package.get("git") or "")

        if "git" in package and not _is_pinned_revision(package.get("revision")):
            findings.append(
                _finding(
                    rule_id="DBT-SEC-008",
                    severity="high",
                    title="dbt package is not pinned to an immutable revision",
                    message=f"Package {package_label!r} is installed from git without a tag or commit SHA revision.",
                    path=path,
                    line=_line_for_key(content, "git"),
                    remediation="Pin git packages to a release tag or commit SHA instead of main/master/latest.",
                    compliance=["SLSA-Source-L2", "NIST-CSF-ID.SC-4"],
                )
            )
        elif "package" in package and (not isinstance(version, str) or not version.strip()):
            findings.append(
                _finding(
                    rule_id="DBT-SEC-008",
                    severity="medium",
                    title="dbt Hub package version is unpinned",
                    message=f"Package {package_label!r} does not declare a version.",
                    path=path,
                    line=_line_for_key(content, "package"),
                    remediation="Pin dbt Hub packages to an explicit version range or exact release.",
                    compliance=["SLSA-Source-L2", "NIST-CSF-ID.SC-4"],
                )
            )

        if git:
            parsed = urlparse(git)
            ssh_style = bool(re.match(r"^[\w.-]+@[\w.-]+:", git))
            if not ssh_style and parsed.scheme not in {"https", "ssh", "git+https"}:
                findings.append(
                    _finding(
                        rule_id="DBT-SEC-010",
                        severity="high",
                        title="dbt package uses untrusted git transport",
                        message=f"Package {package_label!r} uses git source {git!r}, which is not HTTPS or SSH.",
                        path=path,
                        line=_line_for_key(content, "git"),
                        remediation="Use HTTPS or SSH git remotes and pin the package to an immutable revision.",
                        compliance=["SLSA-Source-L2", "NIST-CSF-ID.SC-4"],
                    )
                )
            if ("github.com" not in git and "gitlab.com" not in git and "bitbucket.org" not in git) and not _is_pinned_revision(
                package.get("revision")
            ):
                findings.append(
                    _finding(
                        rule_id="DBT-SEC-009",
                        severity="medium",
                        title="Private dbt git package lacks integrity pin",
                        message=f"Private or self-hosted git package {package_label!r} is not pinned to a tag or commit SHA.",
                        path=path,
                        line=_line_for_key(content, "git"),
                        remediation="Pin private dbt packages to a signed tag or commit SHA and review repository trust.",
                        compliance=["SLSA-Source-L2", "NIST-CSF-ID.SC-4"],
                    )
                )

    return findings


def _scan_sql(path: Path) -> list[IaCFinding]:
    content = _read_text(path)
    findings: list[IaCFinding] = []

    if _VAR_RAW_SQL_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-011",
                severity="medium",
                title="dbt var() is rendered directly into SQL",
                message="A var() expression is rendered outside quotes, which can become SQL injection if the variable is user-controlled.",
                path=path,
                line=_line_for_pattern(content, _VAR_RAW_SQL_RE),
                remediation="Use typed filters, adapter quoting, whitelisted values, or explicit string quoting around var() expressions.",
            )
        )

    if _RUN_QUERY_INPUT_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-012",
                severity="high",
                title="run_query() uses user-controlled input",
                message="run_query() is constructed with var() or env_var(), which can execute dynamic SQL at compile/run time.",
                path=path,
                line=_line_for_pattern(content, _RUN_QUERY_INPUT_RE),
                remediation="Avoid dynamic run_query() input or strictly validate against an allowlist before constructing SQL.",
            )
        )

    if _POST_HOOK_RE.search(content) and _GRANT_ALL_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-013",
                severity="high",
                title="dbt post-hook grants ALL privileges",
                message="A dbt SQL file contains a post-hook with GRANT ALL.",
                path=path,
                line=_line_for_pattern(content, _GRANT_ALL_RE),
                remediation="Grant minimum required privileges to a specific role and avoid broad ALL grants.",
            )
        )

    if _LOG_SECRET_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-014",
                severity="medium",
                title="dbt log() may expose sensitive data",
                message="A log() call includes env_var() or secret-like text, which can leak credentials or personal data to dbt logs.",
                path=path,
                line=_line_for_pattern(content, _LOG_SECRET_RE),
                remediation="Avoid logging secrets, tokens, credentials, or sensitive row values.",
            )
        )

    if _ENV_SECRET_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-015",
                severity="medium",
                title="dbt SQL references secret-like environment variable",
                message=(
                    "env_var() references a secret-like name in SQL, which can expose secrets in compiled SQL or warehouse query history."
                ),
                path=path,
                line=_line_for_pattern(content, _ENV_SECRET_RE),
                remediation="Keep secrets in profile authentication fields or warehouse secret integrations, not compiled SQL.",
            )
        )

    return findings


def _scan_ci(path: Path) -> list[IaCFinding]:
    content = _read_text(path)
    if not _DBT_RUN_RE.search(content):
        return []
    findings: list[IaCFinding] = []
    if "--fail-fast" not in content:
        findings.append(
            _finding(
                rule_id="DBT-SEC-016",
                severity="low",
                title="CI runs dbt without --fail-fast",
                message="A workflow runs dbt run without --fail-fast, delaying failure for production deploy pipelines.",
                path=path,
                line=_line_for_pattern(content, _DBT_RUN_RE),
                remediation="Use dbt run --fail-fast in production CI/CD jobs where early failure is preferred.",
                compliance=["NIST-CSF-DE.CM-7"],
            )
        )
    if not _DBT_TEST_RE.search(content):
        findings.append(
            _finding(
                rule_id="DBT-SEC-017",
                severity="medium",
                title="CI runs dbt without dbt test",
                message="A workflow runs dbt run but no dbt test step was found in the same workflow.",
                path=path,
                line=_line_for_pattern(content, _DBT_RUN_RE),
                remediation="Add dbt test after dbt run or document a separate quality gate.",
                compliance=["NIST-CSF-DE.CM-7"],
            )
        )
    return findings


def _scan_seed(path: Path) -> list[IaCFinding]:
    try:
        first_line = path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (IndexError, OSError):
        return []
    if not _SENSITIVE_SEED_HEADER_RE.search(first_line):
        return []
    return [
        _finding(
            rule_id="DBT-SEC-018",
            severity="medium",
            title="dbt seed file contains sensitive-looking columns",
            message="A committed dbt seed CSV contains sensitive-looking headers such as email, SSN, phone, address, or payment data.",
            path=path,
            line=1,
            remediation="Do not commit sensitive seed data; use synthetic fixtures, masking, or secure warehouse seed sources.",
            compliance=["NIST-CSF-PR.DS-1", "SOC2-CC6.6"],
        )
    ]


def is_dbt_file(path: Path, root: Path | None = None) -> bool:
    """Return True when a path belongs to a dbt project scan surface."""
    name = path.name
    if name in _DBT_PROJECT_NAMES | _DBT_PROFILE_NAMES | _DBT_PACKAGE_NAMES:
        return True
    parts = {part.lower() for part in path.parts}
    if path.suffix == ".sql" and {"models", "macros"} & parts:
        return True
    if path.suffix == ".csv" and "seeds" in parts:
        return True
    if path.suffix in {".yml", ".yaml"} and all(part in parts for part in _CI_WORKFLOW_PARTS):
        content = _read_text(path)
        return bool(_DBT_RUN_RE.search(content))
    if root is not None and (root / "dbt_project.yml").exists() and path.suffix == ".sql":
        return "target" not in parts and "dbt_packages" not in parts
    return False


def scan_dbt_file(path: Path, root: Path | None = None) -> list[IaCFinding]:
    """Scan a single dbt-related file."""
    del root
    if path.name in _DBT_PROFILE_NAMES:
        return _scan_profiles(path)
    if path.name in _DBT_PROJECT_NAMES:
        return _scan_dbt_project(path)
    if path.name in _DBT_PACKAGE_NAMES:
        return _scan_packages(path)
    if path.suffix == ".sql":
        return _scan_sql(path)
    if path.suffix == ".csv":
        return _scan_seed(path)
    if path.suffix in {".yml", ".yaml"}:
        return _scan_ci(path)
    return []
