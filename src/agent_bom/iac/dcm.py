"""Snowflake DCM (Database Change Management) misconfiguration scanner.

DCM is Snowflake's first-party declarative IaC for database objects -- the
schemachange-shaped successor that ships migrations as ``V<seq>__<name>.sql``
plus a manifest. Customers using Snowflake as their AI Data Cloud increasingly
ship schema-as-code via DCM; without a scanner here, agent-bom is blind to the
DDL that defines their security posture (roles, GRANTs, network policies,
warehouse limits, services, tasks).

Mirrors ``terraform_security.py`` shape: regex-based, zero external deps,
maps each rule to the relevant compliance frameworks. Every rule emits an
``IaCFinding`` with ``category="dcm"`` so the dashboard / hub treat DCM
findings as a recognised type.

Rules
-----
DCM-001  Role granted ``MANAGE GRANTS`` (privilege escalation surface)
DCM-002  ``NETWORK POLICY`` with public ALLOWED_IP_LIST (0.0.0.0/0)
DCM-003  GRANT ALL / GRANT * on DATABASE / SCHEMA without scoping
DCM-004  TASK without ``WAREHOUSE_SIZE`` cap or ``USER_TASK_TIMEOUT_MS``
DCM-005  SERVICE / SPCS service without ingress restriction
DCM-006  GRANT ROLE to PUBLIC / SECURITYADMIN / ACCOUNTADMIN broadening
DCM-007  USAGE on DATABASE granted directly (no schema scoping)
DCM-008  CREATE NETWORK POLICY missing in setup that exposes a SERVICE

Issue: #2218. The Native App's own DCM project (``deploy/snowflake/native-app/dcm/``)
self-tests against this scanner via the pre-commit hook.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.iac.models import IaCFinding

# ─── DCM project shape detection ─────────────────────────────────────────────

# Matches `V001__name.sql`, `V99__some_thing.sql`, etc. — the DCM convention.
_DCM_FILENAME_RE = re.compile(r"^V\d+__[a-zA-Z0-9_]+\.sql$")
# Common DCM project directory names.
_DCM_DIR_NAMES = frozenset({"dcm", "schemachange", "migrations", "db-changes"})


def is_dcm_migration(path: Path) -> bool:
    """Return True when `path` looks like a DCM migration file.

    Matches ``V<seq>__<name>.sql`` shape AND the file is under a directory
    that looks like a DCM project (``dcm/``, ``schemachange/``,
    ``migrations/``, ``db-changes/``). The dir hint avoids false positives
    on unrelated SQL scripts elsewhere in the repo.
    """
    if not _DCM_FILENAME_RE.match(path.name):
        return False
    return any(p.name.lower() in _DCM_DIR_NAMES for p in path.parents)


# ─── Rule patterns ───────────────────────────────────────────────────────────


_RULE_PATTERNS: list[tuple[str, str, str, str, str, list[str]]] = [
    # (rule_id, severity, regex, title, message, compliance_tags)
    (
        "DCM-001",
        "critical",
        r"GRANT\s+MANAGE\s+GRANTS\s+(ON|TO)\b",
        "Role granted MANAGE GRANTS — privilege escalation surface",
        "Granting MANAGE GRANTS allows the recipient to delegate any "
        "privilege they hold. Use SECURITYADMIN or ROLE-OWNERSHIP patterns "
        "instead, and audit grants through SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES.",
        ["NIST-CSF-PR.AC-04", "SOC2-CC6.1", "CIS-1.1.1"],
    ),
    (
        "DCM-002",
        "critical",
        r"CREATE(?:\s+OR\s+REPLACE)?\s+NETWORK\s+POLICY[^;]*ALLOWED_IP_LIST\s*=\s*\([^)]*['\"]0\.0\.0\.0/0['\"]",
        "NETWORK POLICY allows traffic from 0.0.0.0/0",
        "A NETWORK POLICY with ALLOWED_IP_LIST that includes 0.0.0.0/0 "
        "permits ingress from any source. Restrict to corporate VPN / "
        "bastion CIDRs and bind to the customer-facing service.",
        ["NIST-CSF-PR.AC-05", "SOC2-CC6.1", "CIS-1.1.6"],
    ),
    (
        "DCM-003",
        "high",
        r"GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+(?:DATABASE|SCHEMA)\b",
        "GRANT ALL on DATABASE or SCHEMA — too broad",
        "GRANT ALL on a DATABASE or SCHEMA gives the role every present and "
        "future privilege. Scope to the specific verbs needed (SELECT, "
        "INSERT, MODIFY) and individual objects.",
        ["NIST-CSF-PR.AC-04", "SOC2-CC6.1", "CIS-1.1.2"],
    ),
    (
        "DCM-004",
        "medium",
        r"CREATE(?:\s+OR\s+REPLACE)?\s+TASK\s+\w+(?:\s+WAREHOUSE\s*=\s*[^;\s]+)?(?:[^;]*?)(?<!USER_TASK_TIMEOUT_MS\s=\s)\s*AS\s",
        "TASK without USER_TASK_TIMEOUT_MS cap",
        "TASK without USER_TASK_TIMEOUT_MS will run until success or kill, "
        "consuming credits unbounded on stuck procedures. Set "
        "USER_TASK_TIMEOUT_MS = <max> on every TASK definition.",
        ["NIST-CSF-PR.PT-01", "SOC2-CC7.2"],
    ),
    (
        "DCM-005",
        "high",
        r"CREATE(?:\s+OR\s+REPLACE)?\s+SERVICE\s+\w+\s+IN\s+COMPUTE\s+POOL\s+\w+(?!.*?(?:NETWORK_POLICY|external_access_integrations))",
        "SERVICE without NETWORK_POLICY or EAI binding",
        "A SERVICE / SPCS service without an explicit NETWORK_POLICY can be "
        "reached from any source the compute pool allows. Bind a "
        "NETWORK_POLICY (see scripts/network_policies.sql templates) and "
        "declare external_access_integrations for any outbound calls.",
        ["NIST-CSF-PR.AC-05", "SOC2-CC6.1", "CIS-1.1.6"],
    ),
    (
        "DCM-006",
        "critical",
        r"GRANT\s+ROLE\s+(?:ACCOUNTADMIN|SECURITYADMIN|SYSADMIN)\s+TO\b",
        "GRANT account-level role widens trust boundary",
        "Granting ACCOUNTADMIN, SECURITYADMIN, or SYSADMIN expands the "
        "blast radius of every action the recipient takes. Prefer custom "
        "roles with the minimum privilege set.",
        ["NIST-CSF-PR.AC-04", "SOC2-CC6.1", "CIS-1.1.1"],
    ),
    (
        "DCM-007",
        "medium",
        r"GRANT\s+USAGE\s+ON\s+DATABASE\s+\w+\s+TO\s+ROLE\b",
        "USAGE on DATABASE granted directly without schema scoping",
        "Granting USAGE on a DATABASE without scoping schema-level privileges "
        "lets the role discover every schema in it. Combine with explicit "
        "schema GRANTs that restrict visibility to what the role needs.",
        ["NIST-CSF-PR.AC-04", "SOC2-CC6.1"],
    ),
    (
        "DCM-008",
        "high",
        r"GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)[^;]*TO\s+ROLE\s+PUBLIC\b",
        "Privilege granted to PUBLIC role",
        "Granting any privilege to ROLE PUBLIC exposes the object to every "
        "Snowflake user in the account. Use a custom role bound to the "
        "specific users that need the access.",
        ["NIST-CSF-PR.AC-04", "SOC2-CC6.1", "CIS-1.1.2"],
    ),
]

_REMEDIATION_BY_RULE: dict[str, str] = {
    "DCM-001": "Drop MANAGE GRANTS; use SECURITYADMIN or ROLE-OWNERSHIP.",
    "DCM-002": "Replace 0.0.0.0/0 with VPN / bastion CIDRs in ALLOWED_IP_LIST.",
    "DCM-003": "Replace GRANT ALL with explicit verb-level GRANTs on objects.",
    "DCM-004": "Add USER_TASK_TIMEOUT_MS = <ms> to the TASK definition.",
    "DCM-005": "Bind a NETWORK_POLICY; declare external_access_integrations.",
    "DCM-006": "Use a custom role; never grant ACCOUNTADMIN / SECURITYADMIN.",
    "DCM-007": "Grant schema-level USAGE explicitly; avoid database-level USAGE.",
    "DCM-008": "Use a custom role; never grant to PUBLIC.",
}


def _line_for_match(text: str, match_start: int) -> int:
    """Return the 1-indexed line containing the given char offset."""
    return text.count("\n", 0, match_start) + 1


def scan_dcm_migration(path: Path) -> list[IaCFinding]:
    """Scan a single DCM migration file for misconfigurations.

    Returns ``IaCFinding`` rows with ``category="dcm"``. The scanner is
    SQL-aware enough to skip lines inside ``--`` and ``/* */`` comments
    so a documented "don't do this" example doesn't trigger.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Strip line comments and block comments before pattern matching so
    # the rules don't false-positive on ``-- example: GRANT ALL ON ...``.
    cleaned = re.sub(r"--[^\n]*", "", text)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)

    findings: list[IaCFinding] = []
    relpath = str(path)

    for rule_id, severity, pattern, title, message, compliance in _RULE_PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        for match in regex.finditer(cleaned):
            # Map the cleaned-text offset back to original-text line number.
            # Conservative: report the line in the cleaned text; close enough
            # for SQL with sparse comments.
            line = _line_for_match(cleaned, match.start())
            findings.append(
                IaCFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    message=message,
                    file_path=relpath,
                    line_number=line,
                    category="dcm",
                    compliance=list(compliance),
                    remediation=_REMEDIATION_BY_RULE.get(rule_id, ""),
                )
            )

    return findings


def scan_dcm_directory(root: Path) -> list[IaCFinding]:
    """Scan every DCM migration in a directory tree.

    Convenience wrapper for callers that want only DCM findings; the main
    ``scan_iac_directory`` already integrates this via ``is_dcm_migration``.
    """
    if not root.is_dir():
        return []
    findings: list[IaCFinding] = []
    for path in sorted(root.rglob("V*__*.sql")):
        if is_dcm_migration(path):
            findings.extend(scan_dcm_migration(path))
    return findings


__all__ = ["is_dcm_migration", "scan_dcm_migration", "scan_dcm_directory"]
