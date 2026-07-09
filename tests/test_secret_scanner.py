from __future__ import annotations

from pathlib import Path

from agent_bom.secret_scanner import scan_secrets


def test_scan_secrets_detects_real_findings_and_skips_test_fixtures(tmp_path: Path):
    (tmp_path / ".env").write_text(
        "DB_PASSWORD=supersecret123\nCONTACT_EMAIL=alice@example.com\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        'OPENAI_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu"\n',
        encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_secrets.py").write_text('PASSWORD = "should-not-trigger"\n', encoding="utf-8")

    result = scan_secrets(tmp_path)

    findings = {(finding.file_path, finding.secret_type, finding.severity) for finding in result.findings}
    assert (".env", ".env password", "high") in findings
    assert (".env", "Email Address", "medium") in findings
    assert ("app.py", "OpenAI API Key", "critical") in findings
    assert all(not finding.file_path.startswith("tests/") for finding in result.findings)
    assert result.files_scanned == 2
    assert all("supersecret123" not in finding.matched_preview for finding in result.findings)
    assert all("alice@example.com" not in finding.matched_preview for finding in result.findings)
    assert all("sk-proj" not in finding.matched_preview for finding in result.findings)
    assert {finding.matched_preview for finding in result.findings} == {
        "[CREDENTIAL_REDACTED]",
        "[SECRET_REDACTED]",
        "[PII_REDACTED]",
    }


def test_scan_secrets_suppresses_doc_pii_but_keeps_doc_credentials(tmp_path: Path):
    doc_key = "sk-" + "proj-" + "abc123def456" + "ghi789jkl012" + "mno345pqr678stu"
    (tmp_path / "README.md").write_text(
        f'Contact security@example.com or test 192.168.1.10 in local docs.\nOPENAI_KEY = "{doc_key}"\n',
        encoding="utf-8",
    )
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "tutorial.md").write_text(
        "Use 10.0.0.5 or 203.0.113.10 as tutorial addresses, then email docs@example.com.\n",
        encoding="utf-8",
    )
    (tmp_path / "notes.txt").write_text("Email docs@example.com from 10.0.0.5.\n", encoding="utf-8")

    result = scan_secrets(tmp_path)

    findings = {(finding.file_path, finding.secret_type, finding.category) for finding in result.findings}
    assert ("README.md", "OpenAI API Key", "credential") in findings
    assert not any(finding.category == "pii" for finding in result.findings)


def test_scan_secrets_keeps_ipv4_pii_in_code_config_and_secret_contexts(tmp_path: Path):
    (tmp_path / "app.py").write_text('ADMIN_BIND_IP = "198.51.100.24"\n', encoding="utf-8")
    (tmp_path / "service.yaml").write_text("upstream_ip: 198.51.100.25\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SERVICE_IP=198.51.100.26\n", encoding="utf-8")
    (tmp_path / "implementation-notes.txt").write_text(
        "The tutorial mentions 198.51.100.27 as an example address.\n",
        encoding="utf-8",
    )

    result = scan_secrets(tmp_path)

    ip_findings = {
        (finding.file_path, finding.secret_type, finding.category)
        for finding in result.findings
        if finding.secret_type == "IP Address (IPv4)"
    }
    assert ip_findings == {
        (".env", "IP Address (IPv4)", "pii"),
        ("app.py", "IP Address (IPv4)", "pii"),
        ("service.yaml", "IP Address (IPv4)", "pii"),
    }


def test_scan_secrets_ignores_oauth_token_minting_assignments(tmp_path: Path):
    # Regression for #3437: minting a token from a method call is not a
    # hardcoded credential and must not raise a CRITICAL finding.
    (tmp_path / "oauth_as.py").write_text(
        "def issue(self, claims):\n"
        "    access_token = self.signing_key.sign(claims)\n"
        "    refresh_token = self.signing_key.sign(refresh_claims)\n"
        "    api_key = build_api_key(user)\n"
        "    return access_token\n",
        encoding="utf-8",
    )

    result = scan_secrets(tmp_path)

    assert result.critical_count == 0
    assert not any(finding.category == "credential" for finding in result.findings)


def test_scan_secrets_still_flags_literal_token_passed_to_a_call(tmp_path: Path):
    # The call-assignment suppression must not hide a real literal secret that
    # merely happens to be passed as a function argument.
    (tmp_path / "loader.py").write_text(
        'aws_key = load("AKIAIOSFODNN7EXAMPLE")\n',
        encoding="utf-8",
    )

    result = scan_secrets(tmp_path)

    assert any(
        finding.secret_type == "AWS Access Key" and finding.severity == "critical" for finding in result.findings
    )


def test_scan_secrets_warns_on_non_directory(tmp_path: Path):
    target = tmp_path / "not-a-dir.txt"
    target.write_text("hello", encoding="utf-8")

    result = scan_secrets(target)

    assert result.total == 0
    assert result.warnings == [f"{target} is not a directory"]


def test_scan_secrets_skips_agent_bom_own_reports(tmp_path: Path):
    """Re-scanning a directory that holds a prior agent-bom report must not flag
    the report's own numeric payload (scan ids, CVSS, timestamps) as PII."""
    # A phone-number-like literal inside our own JSON report must be ignored.
    (tmp_path / "r.json").write_text(
        '{"document_type": "AI-BOM", "summary": {"phone": "415-555-0132"}}',
        encoding="utf-8",
    )
    # SARIF report form.
    (tmp_path / "r.sarif").write_text(
        '{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", '
        '"runs": [{"results": [{"message": {"text": "415-555-0132"}}]}]}',
        encoding="utf-8",
    )
    result = scan_secrets(tmp_path)
    assert result.total == 0
