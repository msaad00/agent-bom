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


def test_scan_secrets_warns_on_non_directory(tmp_path: Path):
    target = tmp_path / "not-a-dir.txt"
    target.write_text("hello", encoding="utf-8")

    result = scan_secrets(target)

    assert result.total == 0
    assert result.warnings == [f"{target} is not a directory"]
