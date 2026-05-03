"""Dataset content PII/PHI scanner.

Scans the actual rows of CSV, JSON, and JSONL dataset files for personal data
before model training to flag EU AI Act Art. 10 / GDPR / HIPAA compliance risks.

Supported file types
--------------------
- ``.csv`` — rows sampled up to ``max_rows``
- ``.json`` — list-of-records or single-object (flattened)
- ``.jsonl`` / ``.ndjson`` — one JSON object per line

PII categories detected
-----------------------
email, ssn, credit_card, phone, ip_address, passport (US/UK/EU),
iban, date_of_birth, nhs_number, medicare_id, medical_record_keyword,
drivers_license (US)

Issue: #984
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ─── PII pattern registry ─────────────────────────────────────────────────────
# Each entry: (compiled regex, pii_type, severity)

_PII_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # Email
    (
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.ASCII),
        "email",
        "medium",
    ),
    # US Social Security Number
    (
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        "ssn",
        "high",
    ),
    # Credit / debit card numbers (Visa, Mastercard, Amex, Discover)
    (
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
            r"3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        "credit_card",
        "high",
    ),
    # US/Canada phone
    (
        re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
        "phone",
        "medium",
    ),
    # IPv4 (public ranges only — skip RFC1918)
    (
        re.compile(
            r"\b(?!10\.\d|\b172\.(?:1[6-9]|2\d|3[01])\.\d|\b192\.168\.)"
            r"(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        "ip_address",
        "low",
    ),
    # IBAN (EU bank account)
    (
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
        "iban",
        "high",
    ),
    # US Passport (letter + 8 digits)
    (
        re.compile(r"\b[A-Z]\d{8}\b"),
        "passport",
        "high",
    ),
    # UK NHS number (3 groups of 3 digits)
    (
        re.compile(r"\b\d{3}[-\s]\d{3}[-\s]\d{4}\b"),
        "nhs_number",
        "high",
    ),
    # Date of birth (ISO, US, EU formats)
    (
        re.compile(
            r"\b(?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}\b"
            r"|\b\d{1,2}[-/]\d{1,2}[-/](?:19|20)\d{2}\b"
        ),
        "date_of_birth",
        "medium",
    ),
    # US Driver's License (state code + 1–9 alphanumeric, 6–14 chars total)
    (
        re.compile(r"\b[A-Z]{1,2}\d{5,12}\b"),
        "drivers_license",
        "medium",
    ),
    # Medical record / ICD-10 code keyword proximity
    (
        re.compile(
            r"\b(?:diagnosis|icd.?10|icd.?9|medical.?record|mrn|"
            r"patient.?id|dob|date.?of.?birth|health.?record)\b",
            re.IGNORECASE,
        ),
        "medical_record_keyword",
        "medium",
    ),
]

# Supported dataset file extensions
_DATASET_EXTENSIONS: frozenset[str] = frozenset({".csv", ".json", ".jsonl", ".ndjson"})

# Default row sample limit (avoid scanning GB-scale files)
_DEFAULT_MAX_ROWS = 1_000

# Max file size before skipping (10 MB)
_MAX_FILE_SIZE = 10 * 1024 * 1024


# ─── Result dataclasses ───────────────────────────────────────────────────────


@dataclass
class PiiFinding:
    """A single PII match found in a dataset row."""

    file_path: str
    row_index: int
    column: str
    pii_type: str
    severity: str
    sample: str  # redacted snippet — never the raw value


@dataclass
class DatasetPiiResult:
    """PII scan results for a single dataset file."""

    file_path: str
    rows_sampled: int
    total_findings: int
    findings_by_type: dict[str, int] = field(default_factory=dict)
    top_findings: list[PiiFinding] = field(default_factory=list)  # capped at 10
    skipped: bool = False
    skip_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "rows_sampled": self.rows_sampled,
            "total_findings": self.total_findings,
            "findings_by_type": self.findings_by_type,
            "top_findings": [
                {
                    "row_index": f.row_index,
                    "column": f.column,
                    "pii_type": f.pii_type,
                    "severity": f.severity,
                    "sample": f.sample,
                }
                for f in self.top_findings
            ],
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }


@dataclass
class DirectoryPiiResult:
    """Aggregated PII scan results for a directory."""

    root: str
    files_scanned: int = 0
    files_with_pii: int = 0
    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    file_results: list[DatasetPiiResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def high_severity_count(self) -> int:
        pii_types_high = {"ssn", "credit_card", "iban", "passport", "nhs_number"}
        return sum(v for k, v in self.findings_by_type.items() if k in pii_types_high)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_with_pii": self.files_with_pii,
            "total_findings": self.total_findings,
            "high_severity_count": self.high_severity_count,
            "findings_by_type": self.findings_by_type,
            "file_results": [r.to_dict() for r in self.file_results],
            "warnings": self.warnings,
        }


# ─── Core scanning ────────────────────────────────────────────────────────────


def _redact(value: str, pii_type: str) -> str:
    """Return a safe redacted representation for display."""
    s = str(value)
    if len(s) <= 4:
        return f"[{pii_type}:***]"
    return f"[{pii_type}:{s[:2]}***{s[-2:]}]"


def _scan_cell(value: str, row_idx: int, col: str, file_path: str) -> list[PiiFinding]:
    """Scan a single cell value against all PII patterns."""
    findings: list[PiiFinding] = []
    seen_types: set[str] = set()
    for pattern, pii_type, severity in _PII_PATTERNS:
        if pii_type in seen_types:
            continue
        if pattern.search(value):
            seen_types.add(pii_type)
            findings.append(
                PiiFinding(
                    file_path=file_path,
                    row_index=row_idx,
                    column=col,
                    pii_type=pii_type,
                    severity=severity,
                    sample=_redact(value, pii_type),
                )
            )
    return findings


def _scan_record(record: dict, row_idx: int, file_path: str) -> list[PiiFinding]:
    """Scan all string values in a flat dict record."""
    findings: list[PiiFinding] = []
    for col, val in record.items():
        if not isinstance(val, (str, int, float)):
            continue
        findings.extend(_scan_cell(str(val), row_idx, str(col), file_path))
    return findings


def scan_csv_file(path: Path, max_rows: int = _DEFAULT_MAX_ROWS) -> DatasetPiiResult:
    """Scan a CSV file for PII in up to ``max_rows`` rows."""
    result = DatasetPiiResult(file_path=str(path), rows_sampled=0, total_findings=0)
    try:
        size = path.stat().st_size
        if size > _MAX_FILE_SIZE:
            result.skipped = True
            result.skip_reason = f"file too large ({size // 1024} KB > {_MAX_FILE_SIZE // 1024} KB limit)"
            return result

        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.skipped = True
        result.skip_reason = str(exc)
        return result

    all_findings: list[PiiFinding] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row_idx, row in enumerate(reader):
            if row_idx >= max_rows:
                break
            result.rows_sampled += 1
            all_findings.extend(_scan_record(dict(row), row_idx, str(path)))
    except csv.Error as exc:
        result.warnings = [f"CSV parse error: {exc}"]  # type: ignore[attr-defined]

    _aggregate(result, all_findings)
    return result


def scan_json_file(path: Path, max_rows: int = _DEFAULT_MAX_ROWS) -> DatasetPiiResult:
    """Scan a JSON file (list of records) for PII."""
    result = DatasetPiiResult(file_path=str(path), rows_sampled=0, total_findings=0)
    try:
        size = path.stat().st_size
        if size > _MAX_FILE_SIZE:
            result.skipped = True
            result.skip_reason = f"file too large ({size // 1024} KB > {_MAX_FILE_SIZE // 1024} KB limit)"
            return result

        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        result.skipped = True
        result.skip_reason = str(exc)
        return result

    records: list[dict] = []
    if isinstance(data, list):
        records = [r for r in data[:max_rows] if isinstance(r, dict)]
    elif isinstance(data, dict):
        records = [data]

    all_findings: list[PiiFinding] = []
    for row_idx, record in enumerate(records):
        result.rows_sampled += 1
        all_findings.extend(_scan_record(record, row_idx, str(path)))

    _aggregate(result, all_findings)
    return result


def scan_jsonl_file(path: Path, max_rows: int = _DEFAULT_MAX_ROWS) -> DatasetPiiResult:
    """Scan a JSONL/NDJSON file (one JSON object per line) for PII."""
    result = DatasetPiiResult(file_path=str(path), rows_sampled=0, total_findings=0)
    try:
        size = path.stat().st_size
        if size > _MAX_FILE_SIZE:
            result.skipped = True
            result.skip_reason = f"file too large ({size // 1024} KB > {_MAX_FILE_SIZE // 1024} KB limit)"
            return result
    except OSError as exc:
        result.skipped = True
        result.skip_reason = str(exc)
        return result

    all_findings: list[PiiFinding] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for row_idx, line in enumerate(fh):
                if row_idx >= max_rows:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                result.rows_sampled += 1
                all_findings.extend(_scan_record(record, row_idx, str(path)))
    except OSError as exc:
        result.skipped = True
        result.skip_reason = str(exc)
        return result

    _aggregate(result, all_findings)
    return result


def _aggregate(result: DatasetPiiResult, findings: list[PiiFinding]) -> None:
    """Populate aggregated counts and top_findings from a raw findings list."""
    result.total_findings = len(findings)
    for f in findings:
        result.findings_by_type[f.pii_type] = result.findings_by_type.get(f.pii_type, 0) + 1
    result.top_findings = findings[:10]


def scan_dataset_file(path: Path, max_rows: int = _DEFAULT_MAX_ROWS) -> DatasetPiiResult | None:
    """Dispatch to the appropriate scanner based on file extension.

    Returns None if the extension is not supported.
    """
    ext = path.suffix.lower()
    if ext == ".csv":
        return scan_csv_file(path, max_rows)
    if ext == ".json":
        return scan_json_file(path, max_rows)
    if ext in {".jsonl", ".ndjson"}:
        return scan_jsonl_file(path, max_rows)
    return None


# ─── Directory scanner ────────────────────────────────────────────────────────

_SKIP_DIRS: frozenset[str] = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"})


def scan_directory_for_pii(
    root: Path,
    *,
    max_rows: int = _DEFAULT_MAX_ROWS,
    max_files: int = 500,
) -> DirectoryPiiResult:
    """Scan CSV/JSON/JSONL files in ``root`` for PII/PHI content.

    Args:
        root: Directory to walk.
        max_rows: Maximum rows to sample per file (default 1 000).
        max_files: Safety cap on total files scanned (default 500).

    Returns:
        A :class:`DirectoryPiiResult` with per-file results and aggregate counts.
    """
    agg = DirectoryPiiResult(root=str(root))

    if not root.is_dir():
        agg.warnings.append(f"Not a directory: {root}")
        return agg

    files_checked = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS or part.startswith(".") for part in path.parts):
            continue
        if path.suffix.lower() not in _DATASET_EXTENSIONS:
            continue
        if files_checked >= max_files:
            agg.warnings.append(f"Reached max_files={max_files} limit; some files not scanned")
            break

        file_result = scan_dataset_file(path, max_rows=max_rows)
        if file_result is None:
            continue

        files_checked += 1
        agg.files_scanned += 1
        agg.file_results.append(file_result)

        if file_result.total_findings > 0:
            agg.files_with_pii += 1
            agg.total_findings += file_result.total_findings
            for pii_type, count in file_result.findings_by_type.items():
                agg.findings_by_type[pii_type] = agg.findings_by_type.get(pii_type, 0) + count

    logger.debug(
        "dataset_pii_scanner: %s — %d files, %d with PII, %d total findings",
        root,
        agg.files_scanned,
        agg.files_with_pii,
        agg.total_findings,
    )
    return agg
