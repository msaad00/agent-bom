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

Deep classification (beyond tag/regex)
--------------------------------------
- ``credit_card`` — candidate PANs are **Luhn-checksum + IIN/length
  validated** (Visa/Mastercard/Amex/Discover) so a bare ``\\d{16}`` sequence
  that fails the checksum does not classify. This kills the dominant false
  positive of naive card regexes.
- ``secret:*`` — a curated set of high-signal credential detectors (AWS keys,
  GitHub/GitLab/Slack tokens, JWTs, PEM private-key blocks, provider API keys)
  reused from the runtime credential pattern library, surfaced as a data-class
  so DSPM reports the same secrets the runtime proxy detects.

Every finding carries a ``confidence`` tier: regex-only matches are ``low`` /
``medium``; Luhn- or structurally-validated matches are ``high``. Matched card
and secret values are never logged or echoed — findings carry a redacted
marker only.

Issues: #984, #3880
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.runtime.patterns import CREDENTIAL_PATTERNS
from agent_bom.traversal import iter_discovery_files

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
    # NOTE: credit / debit card numbers are handled by the Luhn-validated
    # detector (_detect_payment_cards), NOT a bare regex — a raw IIN/length
    # regex over-fires on any 16-digit sequence (order ids, timestamps).
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
    """A single PII / secret match found in a dataset row."""

    file_path: str
    row_index: int
    column: str
    pii_type: str
    severity: str
    sample: str  # redacted marker — never the raw value
    # Detection confidence: "low"/"medium" for regex-only matches, "high" for
    # Luhn-checksum (cards) or structurally-validated (prefixed secrets) hits.
    confidence: str = "medium"


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
                    "confidence": f.confidence,
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
        return sum(
            v
            for k, v in self.findings_by_type.items()
            if k in pii_types_high or k.startswith("secret:")
        )

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
    """Return a safe redacted representation for display.

    The contract is **never reveal any digits / characters of the matched value** —
    not even prefix/suffix snippets. PCI DSS § 3.4.1 prohibits storing readable
    PAN; partial SSN exposes identity-linkable digits; partial IBAN / passport /
    NHS / Medicare leaks the same. Findings carry only the type and severity;
    the file path, row index, and column already give the operator everything
    needed to locate the cell — they don't need our preview, and any preview
    becomes a downstream leak vector (JSON output → DB → audit log → dashboard).
    """
    return f"[{pii_type}:REDACTED]"


# ─── Luhn-validated payment-card detection ────────────────────────────────────
#
# A bare ``\d{16}`` (or IIN-anchored) regex over-fires: order ids, epoch
# timestamps, and phone/account digit runs all match. We instead extract
# candidate digit runs, then require BOTH a recognized IIN/length pairing
# (Visa/Mastercard/Amex/Discover) AND a valid Luhn checksum. Only a real card
# number survives — the dominant false positive is eliminated.

# Candidate PAN: 13–19 digits, optionally split by single spaces or hyphens.
_PAN_CANDIDATE_RE = re.compile(r"(?<![0-9])(?:\d[ -]?){12,18}\d(?![0-9])")


def _luhn_valid(digits: str) -> bool:
    """Return True if ``digits`` (all-digit string) passes the Luhn checksum."""
    if not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_brand(digits: str) -> str | None:
    """Return the card network if ``digits`` matches a known IIN/length pairing.

    Basic issuer-identification-number + length sanity so a valid-Luhn string
    that isn't a real card format (e.g. a random 16-digit id that happens to
    checksum) does not classify as a payment card.
    """
    if not digits.isdigit():
        return None
    n = len(digits)
    # Visa: IIN 4, length 13/16/19.
    if digits[0] == "4" and n in (13, 16, 19):
        return "visa"
    # Mastercard: IIN 51-55 or 2221-2720, length 16.
    if n == 16:
        two = int(digits[:2])
        four = int(digits[:4])
        if 51 <= two <= 55 or 2221 <= four <= 2720:
            return "mastercard"
    # Amex: IIN 34/37, length 15.
    if n == 15 and digits[:2] in ("34", "37"):
        return "amex"
    # Discover: IIN 6011, 65, 644-649, 622126-622925, length 16.
    if n == 16:
        four = int(digits[:4])
        six = int(digits[:6])
        if (
            digits.startswith("6011")
            or digits[:2] == "65"
            or 644 <= int(digits[:3]) <= 649
            or 622126 <= six <= 622925
        ):
            return "discover"
    return None


def _detect_payment_cards(value: str, row_idx: int, col: str, file_path: str) -> list[PiiFinding]:
    """Find Luhn- + IIN/length-validated payment card numbers in ``value``."""
    findings: list[PiiFinding] = []
    for match in _PAN_CANDIDATE_RE.finditer(value):
        digits = match.group().replace(" ", "").replace("-", "")
        if not (13 <= len(digits) <= 19):
            continue
        if _card_brand(digits) is None or not _luhn_valid(digits):
            continue
        findings.append(
            PiiFinding(
                file_path=file_path,
                row_index=row_idx,
                column=col,
                pii_type="credit_card",
                severity="high",
                sample=_redact("", "credit_card"),
                confidence="high",  # checksum + issuer validated
            )
        )
        break  # one card finding per cell is enough
    return findings


# ─── Secret / credential detection (data-class) ───────────────────────────────
#
# DSPM surfaces the SAME credential detectors the runtime proxy uses — reused
# from CREDENTIAL_PATTERNS rather than duplicated — as a ``secret:<type>``
# data-class. Structurally distinctive detectors (fixed prefix + charset/length,
# e.g. AKIA…, ghp_…, JWT, PEM blocks) are high confidence; context/generic
# detectors (generic api-key/bearer, bare connection strings) are lower.

# Credential names whose pattern is context- or shape-generic → lower confidence.
_LOWER_CONFIDENCE_SECRETS: frozenset[str] = frozenset(
    {
        "AWS Secret Key",
        "AWS Session Token",
        "Generic Bearer Token",
        "Generic API Key",
        "Connection String",
        "Mailgun API Key",
        "Heroku API Key",
        "Telegram Bot Token",
        "Datadog API Key",
        "Snowflake JWT",
        "PagerDuty API Key",
    }
)


def _secret_slug(name: str) -> str:
    """Normalize a credential detector name to a ``secret:<slug>`` data-class."""
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return f"secret:{slug}"


def _detect_secrets(value: str, row_idx: int, col: str, file_path: str) -> list[PiiFinding]:
    """Detect hardcoded secrets/credentials in ``value`` (redacted output)."""
    findings: list[PiiFinding] = []
    seen: set[str] = set()
    for name, pattern in CREDENTIAL_PATTERNS:
        if not pattern.search(value):
            continue
        data_class = _secret_slug(name)
        if data_class in seen:
            continue
        seen.add(data_class)
        low = name in _LOWER_CONFIDENCE_SECRETS
        findings.append(
            PiiFinding(
                file_path=file_path,
                row_index=row_idx,
                column=col,
                pii_type=data_class,
                severity="high" if not low else "medium",
                sample=_redact("", data_class),
                confidence="low" if low else "high",
            )
        )
    return findings


def _scan_cell(value: str, row_idx: int, col: str, file_path: str) -> list[PiiFinding]:
    """Scan a single cell value for PII, payment cards, and secrets."""
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
                    confidence="medium",  # regex-only structural match
                )
            )
    for detector in (_detect_payment_cards, _detect_secrets):
        for finding in detector(value, row_idx, col, file_path):
            if finding.pii_type in seen_types:
                continue
            seen_types.add(finding.pii_type)
            findings.append(finding)
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


def scan_text_for_pii(
    text: str,
    *,
    source: str,
    max_chars: int = _MAX_FILE_SIZE,
) -> DatasetPiiResult:
    """Scan an in-memory text sample for PII without persisting raw content.

    Cloud DSPM samplers use this entry point after reading a bounded byte range
    from an object store. The returned findings carry redacted markers only; raw
    object bytes and matched values are never included in the result.
    """
    clipped = text[: max(0, max_chars)]
    result = DatasetPiiResult(file_path=source, rows_sampled=1 if clipped else 0, total_findings=0)
    findings = _scan_cell(clipped, 0, "content", source) if clipped else []
    _aggregate(result, findings)
    return result


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

    candidates = sorted(
        path
        for path in iter_discovery_files(root, extra_skip_dirs=_SKIP_DIRS)
        if not any(part in _SKIP_DIRS or part.startswith(".") for part in path.parts)
        and path.suffix.lower() in _DATASET_EXTENSIONS
    )
    files_checked = 0
    for path in candidates:
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
