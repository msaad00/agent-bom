"""PII findings must not masquerade as credential exposure.

``secret_dict_to_finding`` previously hardcoded ``FindingType.CREDENTIAL_EXPOSURE``
for every secret-scanner row regardless of its ``category``. A matched IPv4
literal therefore reached operators as a credential exposure whose remediation
said to *rotate* it. A real repository produced 475 such rows, and the single
most common matched value was ``127.0.0.1``.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.finding import FindingType, secret_dict_to_finding
from agent_bom.secret_scanner import scan_secrets


def _pii_row(secret_type: str = "US SSN") -> dict:
    return {
        "file": "app/config.py",
        "line": 12,
        "type": secret_type,
        "severity": "medium",
        "preview": "[PII_REDACTED]",
        "category": "pii",
    }


def _credential_row() -> dict:
    return {
        "file": "app/config.py",
        "line": 3,
        "type": "AWS Access Key",
        "severity": "critical",
        "preview": "[SECRET_REDACTED]",
        "category": "credential",
    }


def test_pii_row_is_not_credential_exposure() -> None:
    finding = secret_dict_to_finding(_pii_row())
    assert finding.finding_type is not FindingType.CREDENTIAL_EXPOSURE


def test_credential_row_stays_credential_exposure() -> None:
    finding = secret_dict_to_finding(_credential_row())
    assert finding.finding_type is FindingType.CREDENTIAL_EXPOSURE


def test_pii_remediation_does_not_tell_operators_to_rotate() -> None:
    finding = secret_dict_to_finding(_pii_row())
    text = f"{finding.description} {finding.remediation_guidance}".lower()
    assert "rotate" not in text, f"PII finding advises rotation: {text}"
    assert "secret manager" not in text


def test_pii_and_credential_types_stay_distinct_in_json() -> None:
    pii = secret_dict_to_finding(_pii_row()).to_dict()
    cred = secret_dict_to_finding(_credential_row()).to_dict()
    assert pii["finding_type"] != cred["finding_type"]


def test_pii_and_credential_stay_distinct_in_sarif() -> None:
    """The SARIF rule *family* is derived from the finding type, so the two must
    not share a family. Guarding on the family (not the category token, which
    already differs) is what actually pins the type split."""
    from agent_bom.output.sarif import _unified_finding_rule_id

    pii_family = _unified_finding_rule_id(secret_dict_to_finding(_pii_row())).split("/")[1]
    cred_family = _unified_finding_rule_id(secret_dict_to_finding(_credential_row())).split("/")[1]
    assert pii_family != cred_family, f"PII and credential share SARIF family {pii_family}"


# ── Non-routable / documentation IPv4 literals are not PII ───────────────────

_LOCAL_IPS = ["127.0.0.1", "0.0.0.0", "192.0.2.10", "198.51.100.4", "203.0.113.77",
              "10.0.0.5", "192.168.1.1", "169.254.1.1", "255.255.255.255"]


def test_localhost_ip_is_not_reported(tmp_path: Path) -> None:
    (tmp_path / "settings.yml").write_text("\n".join(f"host: {ip}" for ip in _LOCAL_IPS) + "\n")

    findings = scan_secrets(str(tmp_path)).findings
    ip_findings = [f for f in findings if "IP Address" in f.secret_type]
    assert ip_findings == [], f"non-routable literals reported as PII: {[f.file_path for f in ip_findings]}"


def test_routable_ip_with_pii_context_is_still_reported(tmp_path: Path) -> None:
    """Do not weaken real detection: a routable literal still reports, at medium."""
    (tmp_path / "settings.yml").write_text("client_ip: 8.8.8.8\nremote_host: 52.94.236.248\n")

    findings = [f for f in scan_secrets(str(tmp_path)).findings if "IP Address" in f.secret_type]
    assert findings, "routable IPv4 should still be reported"
    assert all(f.severity == "medium" for f in findings)


def test_real_credential_pattern_is_not_weakened(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')

    findings = scan_secrets(str(tmp_path)).findings
    assert any(f.category == "credential" for f in findings)


def test_pii_row_projects_to_its_own_finding_class() -> None:
    """The CLI/API projection must not bucket personal data as a secret.

    ``finding_class_for_row`` also classifies on ``source == "SECRET_SCAN"``,
    which both categories share — so the type has to be decided first.
    """
    from agent_bom.finding_scope import FINDING_CLASSES, finding_class_for_row

    assert "pii" in FINDING_CLASSES
    assert finding_class_for_row({"finding_type": "PII_EXPOSURE", "source": "SECRET_SCAN"}) == "pii"
    assert finding_class_for_row({"finding_type": "CREDENTIAL_EXPOSURE", "source": "SECRET_SCAN"}) == "secret"


def test_pii_finding_stays_in_the_repo_posture_lane() -> None:
    """Routing must be type-decisive, not a fallthrough to the source."""
    from agent_bom.finding import FindingSource, FindingType
    from agent_bom.finding_scope import security_domain_for

    assert security_domain_for(FindingSource.SECRET_SCAN, FindingType.PII_EXPOSURE, {}) == "aspm"
