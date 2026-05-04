"""Tests for agent_bom.parsers.dataset_pii_scanner (#984)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from agent_bom.parsers.dataset_pii_scanner import (
    DatasetPiiResult,
    _redact,
    _scan_cell,
    scan_csv_file,
    scan_dataset_file,
    scan_directory_for_pii,
    scan_json_file,
    scan_jsonl_file,
)

# ─── _redact ─────────────────────────────────────────────────────────────────


def test_redact_never_reveals_any_characters():
    """Trust contract: redaction must NEVER reveal any chars of the matched
    value. PCI DSS § 3.4.1 prohibits storing readable PAN; partial SSN /
    IBAN / passport / NHS leaks identity-linkable data. The finding's
    file_path + row_index + column already locate the cell — no preview
    needed. Any preview becomes a downstream leak vector (JSON → DB →
    audit log → dashboard)."""
    # Short value
    assert _redact("123", "ssn") == "[ssn:REDACTED]"
    # Credit card — must not leak any digits
    cc = "4532123456789012"
    r = _redact(cc, "credit_card")
    assert r == "[credit_card:REDACTED]"
    for digit in cc:
        assert digit not in r, f"redaction leaked digit {digit!r}: {r!r}"
    # SSN — must not leak any digits
    ssn = "123-45-6789"
    r = _redact(ssn, "ssn")
    assert r == "[ssn:REDACTED]"
    for ch in "1234567890":
        assert ch not in r
    # Email — full value must not appear
    email = "john@example.com"
    r = _redact(email, "email")
    assert r == "[email:REDACTED]"
    assert "john" not in r
    assert "example" not in r
    assert "@" not in r


# ─── _scan_cell ──────────────────────────────────────────────────────────────


def test_scan_cell_email():
    findings = _scan_cell("user@example.com", 0, "email_col", "f.csv")
    assert len(findings) == 1
    assert findings[0].pii_type == "email"
    assert findings[0].severity == "medium"


def test_scan_cell_ssn():
    findings = _scan_cell("123-45-6789", 0, "ssn_col", "f.csv")
    types = {f.pii_type for f in findings}
    assert "ssn" in types


def test_scan_cell_credit_card():
    findings = _scan_cell("4111111111111111", 0, "card", "f.csv")
    types = {f.pii_type for f in findings}
    assert "credit_card" in types


def test_scan_cell_no_match():
    findings = _scan_cell("hello world no pii here", 0, "text", "f.csv")
    assert findings == []


def test_scan_cell_deduplicates_same_type():
    # Two emails in same cell should produce only one finding per type
    findings = _scan_cell("a@b.com and c@d.com", 0, "col", "f.csv")
    email_findings = [f for f in findings if f.pii_type == "email"]
    assert len(email_findings) == 1


def test_scan_cell_medical_keyword():
    findings = _scan_cell("diagnosis: hypertension", 0, "notes", "f.csv")
    types = {f.pii_type for f in findings}
    assert "medical_record_keyword" in types


# ─── scan_csv_file ───────────────────────────────────────────────────────────


def test_scan_csv_file_detects_email(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["name", "email"])
        writer.writeheader()
        writer.writerow({"name": "Alice", "email": "alice@example.com"})
    result = scan_csv_file(f)
    assert result.total_findings >= 1
    assert "email" in result.findings_by_type
    assert result.rows_sampled == 1


def test_scan_csv_file_detects_ssn(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["id", "ssn"])
        writer.writeheader()
        writer.writerow({"id": "1", "ssn": "123-45-6789"})
    result = scan_csv_file(f)
    assert "ssn" in result.findings_by_type


def test_scan_csv_file_clean(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["item", "qty"])
        writer.writeheader()
        writer.writerow({"item": "widget", "qty": "5"})
    result = scan_csv_file(f)
    assert result.total_findings == 0


def test_scan_csv_file_max_rows(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["email"])
        writer.writeheader()
        for i in range(10):
            writer.writerow({"email": f"user{i}@test.com"})
    result = scan_csv_file(f, max_rows=3)
    assert result.rows_sampled == 3


def test_scan_csv_file_missing():
    result = scan_csv_file(Path("/nonexistent/file.csv"))
    assert result.skipped is True
    assert result.skip_reason != ""


def test_scan_csv_file_oversized(tmp_path, monkeypatch):
    f = tmp_path / "big.csv"
    f.write_text("email\nalice@example.com\n")
    monkeypatch.setattr("agent_bom.parsers.dataset_pii_scanner._MAX_FILE_SIZE", 0)
    result = scan_csv_file(f)
    assert result.skipped is True
    assert "too large" in result.skip_reason


# ─── scan_json_file ──────────────────────────────────────────────────────────


def test_scan_json_file_list(tmp_path):
    f = tmp_path / "records.json"
    f.write_text(json.dumps([{"user": "alice@example.com"}, {"user": "bob"}]))
    result = scan_json_file(f)
    assert "email" in result.findings_by_type
    assert result.rows_sampled == 2


def test_scan_json_file_single_object(tmp_path):
    f = tmp_path / "record.json"
    f.write_text(json.dumps({"ssn": "123-45-6789", "name": "Bob"}))
    result = scan_json_file(f)
    assert "ssn" in result.findings_by_type


def test_scan_json_file_clean(tmp_path):
    f = tmp_path / "clean.json"
    f.write_text(json.dumps([{"key": "value"}, {"key": "other"}]))
    result = scan_json_file(f)
    assert result.total_findings == 0


def test_scan_json_file_invalid(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not valid json")
    result = scan_json_file(f)
    assert result.skipped is True


# ─── scan_jsonl_file ─────────────────────────────────────────────────────────


def test_scan_jsonl_file_detects_pii(tmp_path):
    f = tmp_path / "data.jsonl"
    lines = [
        json.dumps({"email": "alice@example.com"}),
        json.dumps({"name": "clean"}),
        json.dumps({"card": "4111111111111111"}),
    ]
    f.write_text("\n".join(lines))
    result = scan_jsonl_file(f)
    assert "email" in result.findings_by_type
    assert "credit_card" in result.findings_by_type
    assert result.rows_sampled == 3


def test_scan_jsonl_file_skips_blank_lines(tmp_path):
    f = tmp_path / "data.ndjson"
    f.write_text('\n{"name": "clean"}\n\n{"key": "val"}\n')
    result = scan_jsonl_file(f)
    assert result.rows_sampled == 2


def test_scan_jsonl_file_max_rows(tmp_path):
    f = tmp_path / "data.jsonl"
    lines = [json.dumps({"email": f"u{i}@test.com"}) for i in range(20)]
    f.write_text("\n".join(lines))
    result = scan_jsonl_file(f, max_rows=5)
    assert result.rows_sampled == 5


# ─── scan_dataset_file ───────────────────────────────────────────────────────


def test_scan_dataset_file_dispatches_csv(tmp_path):
    f = tmp_path / "test.csv"
    f.write_text("name\nalice\n")
    result = scan_dataset_file(f)
    assert isinstance(result, DatasetPiiResult)


def test_scan_dataset_file_dispatches_json(tmp_path):
    f = tmp_path / "test.json"
    f.write_text("[]")
    result = scan_dataset_file(f)
    assert isinstance(result, DatasetPiiResult)


def test_scan_dataset_file_dispatches_jsonl(tmp_path):
    f = tmp_path / "test.jsonl"
    f.write_text('{"k":"v"}\n')
    result = scan_dataset_file(f)
    assert isinstance(result, DatasetPiiResult)


def test_scan_dataset_file_unsupported(tmp_path):
    f = tmp_path / "model.parquet"
    f.touch()
    assert scan_dataset_file(f) is None


# ─── scan_directory_for_pii ──────────────────────────────────────────────────


def test_scan_directory_finds_pii(tmp_path):
    f = tmp_path / "users.csv"
    with f.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["email"])
        writer.writeheader()
        writer.writerow({"email": "alice@example.com"})
    result = scan_directory_for_pii(tmp_path)
    assert result.files_scanned == 1
    assert result.files_with_pii == 1
    assert result.total_findings >= 1
    assert "email" in result.findings_by_type


def test_scan_directory_skips_hidden(tmp_path):
    hidden = tmp_path / ".venv"
    hidden.mkdir()
    f = hidden / "data.csv"
    with f.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["ssn"])
        writer.writeheader()
        writer.writerow({"ssn": "123-45-6789"})
    result = scan_directory_for_pii(tmp_path)
    assert result.files_scanned == 0


def test_scan_directory_skips_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    f = nm / "data.json"
    f.write_text(json.dumps([{"email": "a@b.com"}]))
    result = scan_directory_for_pii(tmp_path)
    assert result.files_scanned == 0


def test_scan_directory_empty(tmp_path):
    result = scan_directory_for_pii(tmp_path)
    assert result.files_scanned == 0
    assert result.total_findings == 0


def test_scan_directory_not_a_dir(tmp_path):
    f = tmp_path / "file.csv"
    f.write_text("k,v\n1,2\n")
    result = scan_directory_for_pii(f)
    assert len(result.warnings) > 0


def test_scan_directory_max_files(tmp_path):
    for i in range(10):
        f = tmp_path / f"data{i}.csv"
        with f.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["val"])
            writer.writeheader()
            writer.writerow({"val": "clean"})
    result = scan_directory_for_pii(tmp_path, max_files=3)
    assert result.files_scanned == 3
    assert any("max_files" in w for w in result.warnings)


def test_scan_directory_to_dict(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["email"])
        writer.writeheader()
        writer.writerow({"email": "bob@example.com"})
    result = scan_directory_for_pii(tmp_path)
    d = result.to_dict()
    assert "files_scanned" in d
    assert "total_findings" in d
    assert "findings_by_type" in d
    assert "file_results" in d


def test_scan_directory_high_severity_count(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["ssn", "email"])
        writer.writeheader()
        writer.writerow({"ssn": "123-45-6789", "email": "a@b.com"})
    result = scan_directory_for_pii(tmp_path)
    assert result.high_severity_count >= 1


def test_scan_directory_multiple_file_types(tmp_path):
    csv_file = tmp_path / "a.csv"
    with csv_file.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["email"])
        writer.writeheader()
        writer.writerow({"email": "alice@example.com"})

    json_file = tmp_path / "b.json"
    json_file.write_text(json.dumps([{"ssn": "123-45-6789"}]))

    jsonl_file = tmp_path / "c.jsonl"
    jsonl_file.write_text(json.dumps({"card": "4111111111111111"}) + "\n")

    result = scan_directory_for_pii(tmp_path)
    assert result.files_scanned == 3
    assert result.files_with_pii == 3
