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


def test_scan_secrets_warns_on_non_directory(tmp_path: Path):
    target = tmp_path / "not-a-dir.txt"
    target.write_text("hello", encoding="utf-8")

    result = scan_secrets(target)

    assert result.total == 0
    assert result.warnings == [f"{target} is not a directory"]
