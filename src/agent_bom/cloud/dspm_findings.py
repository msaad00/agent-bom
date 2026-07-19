"""Turn redacted DSPM content classifications into canonical findings (issue #4157).

The object-store and database content classifiers (S3 / GCS / Azure Blob /
database) each write a *redacted* ``content_classification`` block onto their
inventory record: a data-sensitivity verdict, finding types + counts, and a
location — never raw values. This module reads those already-persisted redacted
dicts and maps every content-confirmed sensitive location into a
:class:`~agent_bom.finding.Finding`, so content-confirmed sensitivity flows
through the same findings spine, exports, and graph correlation as every other
finding.

Honesty rules:

- Only a content-confirmed ``sensitive`` / ``review`` location becomes a finding.
  An ``unevaluable`` / ``failed`` / ``skipped`` state never emits one (absence of
  a finding from an unreadable source is not evidence of clean).
- Evidence copies only redacted types/counts/location + coverage — never a raw
  value; the inputs are already redacted.
- Findings are deterministic (stable id from type + asset + title) and
  de-duplicated per location, so re-scanning is idempotent.

The single entry point :func:`build_inventory_dspm_findings` reads a per-provider
inventory payload (the same dict persisted on the scan report), so the database
and Azure scan routes wire it identically.
"""

from __future__ import annotations

from typing import Any, Iterable

from agent_bom.finding import Asset, Finding, FindingSource, FindingType

_HIGH_SENSITIVITY_TYPES = frozenset({"ssn", "credit_card", "iban", "passport", "nhs_number"})
_MEDIUM_SENSITIVITY_TYPES = frozenset({"email", "phone", "date_of_birth", "drivers_license", "medical_record_keyword"})

# Redaction contract copied onto every emitted finding's evidence.
_REDACTION_NOTE = "raw object bytes, database rows, and matched values are not stored"

_SENSITIVE_VERDICTS = frozenset({"sensitive", "review"})


def _severity_for(findings_by_type: dict[str, int]) -> str:
    """Map redacted finding types to a finding severity (never raises)."""
    if any(k in _HIGH_SENSITIVITY_TYPES or str(k).startswith("secret:") for k in findings_by_type):
        return "high"
    if any(k in _MEDIUM_SENSITIVITY_TYPES for k in findings_by_type):
        return "medium"
    return "low"


def _types_summary(findings_by_type: dict[str, int]) -> str:
    """Human-readable, redacted list of detected types + counts (no raw values)."""
    parts = [f"{kind} (x{count})" for kind, count in sorted(findings_by_type.items())]
    return ", ".join(parts)


def _coerce_type_counts(raw: Any) -> dict[str, int]:
    """Coerce a persisted findings_by_type mapping to ``{str: int}`` defensively."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in raw.items():
        try:
            out[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return out


def _make_finding(
    *,
    resource_type: str,
    location: str,
    data_sensitivity: str,
    findings_by_type: dict[str, int],
    total_findings: int,
    coverage_state: str,
    provider: str,
    account_ref: str | None,
    region: str | None,
    environment: str | None,
    sampling: str,
    extra_evidence: dict[str, Any] | None = None,
) -> Finding:
    types = _types_summary(findings_by_type)
    identifier = f"{provider}:{account_ref or ''}:{resource_type}:{location}"
    evidence: dict[str, Any] = {
        "provider": provider,
        "account_ref": account_ref,
        "resource_type": resource_type,
        "location": location,
        "data_sensitivity": data_sensitivity,
        "findings_by_type": dict(findings_by_type),
        "total_findings": total_findings,
        "coverage_state": coverage_state,
        "sampling": sampling,
        "redaction": _REDACTION_NOTE,
    }
    if extra_evidence:
        evidence.update(extra_evidence)
    return Finding(
        finding_type=FindingType.SENSITIVE_DATA,
        source=FindingSource.DSPM,
        asset=Asset(
            name=location,
            asset_type="cloud_resource",
            identifier=identifier,
            location=location,
            provider=provider,
            account_ref=account_ref,
            region=region,
            environment=environment,
        ),
        severity=_severity_for(findings_by_type),
        provider=provider,
        account_ref=account_ref,
        region=region,
        environment=environment,
        title=f"Sensitive data detected in {resource_type} {location}",
        description=(
            f"Content sampling confirmed sensitive data ({data_sensitivity}) in "
            f"{resource_type} {location}: {types}. Redacted evidence only — {_REDACTION_NOTE}."
        ),
        evidence=evidence,
    )


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        out.append(finding)
    return out


def _database_table_findings(
    classification: dict[str, Any],
    *,
    provider: str,
    account_ref: str | None,
    region: str | None,
    environment: str | None,
) -> list[Finding]:
    out: list[Finding] = []
    source = classification.get("source")
    for table in classification.get("tables", []) or []:
        if not isinstance(table, dict):
            continue
        if str(table.get("data_sensitivity")) not in _SENSITIVE_VERDICTS:
            continue
        counts = _coerce_type_counts(table.get("findings_by_type"))
        total = int(table.get("total_findings") or 0)
        if total <= 0 or not counts:
            continue
        location = f"{table.get('schema', '')}.{table.get('table', '')}".strip(".")
        out.append(
            _make_finding(
                resource_type="database table",
                location=location,
                data_sensitivity=str(table.get("data_sensitivity")),
                findings_by_type=counts,
                total_findings=total,
                coverage_state=str(table.get("state") or ""),
                provider=provider,
                account_ref=account_ref,
                region=region,
                environment=environment,
                sampling="bounded read-only SELECT",
                extra_evidence={
                    "source": source,
                    "rows_sampled": int(table.get("rows_sampled") or 0),
                    "columns_sampled": int(table.get("columns_sampled") or 0),
                },
            )
        )
    return out


def _blob_container_findings(
    classification: dict[str, Any],
    *,
    storage_account: str,
    provider: str,
    account_ref: str | None,
    region: str | None,
    environment: str | None,
) -> list[Finding]:
    out: list[Finding] = []
    for container in classification.get("containers", []) or []:
        if not isinstance(container, dict):
            continue
        if str(container.get("data_sensitivity")) not in _SENSITIVE_VERDICTS:
            continue
        counts = _coerce_type_counts(container.get("findings_by_type"))
        total = int(container.get("total_findings") or 0)
        if total <= 0 or not counts:
            continue
        name = str(container.get("container") or "")
        location = f"{storage_account}/{name}"
        out.append(
            _make_finding(
                resource_type="Azure Blob container",
                location=location,
                data_sensitivity=str(container.get("data_sensitivity")),
                findings_by_type=counts,
                total_findings=total,
                coverage_state=str(container.get("status") or ""),
                provider=provider,
                account_ref=account_ref,
                region=region,
                environment=environment,
                sampling="bounded byte-range download",
                extra_evidence={
                    "storage_account": storage_account,
                    "container": name,
                    "objects_sampled": int(container.get("objects_sampled") or 0),
                },
            )
        )
    return out


def build_inventory_dspm_findings(
    inventory: dict[str, Any],
    *,
    provider: str,
    account_ref: str | None = None,
    region: str | None = None,
    environment: str | None = None,
) -> list[Finding]:
    """Emit deterministic, de-duplicated DSPM findings from an inventory payload.

    Reads the redacted ``content_classification`` block on each ``dspm_databases``
    record (per sensitive table) and each ``storage_accounts`` record (per
    sensitive Azure Blob container). Records without a classification, or whose
    classification is unevaluable/clean, emit nothing.
    """
    findings: list[Finding] = []

    for db in inventory.get("dspm_databases", []) or []:
        if not isinstance(db, dict):
            continue
        classification = db.get("content_classification")
        if not isinstance(classification, dict):
            continue
        db_account_ref = account_ref or (f"{provider}:{db.get('account_id')}" if db.get("account_id") else None)
        findings.extend(
            _database_table_findings(
                classification,
                provider=provider,
                account_ref=db_account_ref,
                region=region,
                environment=environment,
            )
        )

    for acct in inventory.get("storage_accounts", []) or []:
        if not isinstance(acct, dict):
            continue
        classification = acct.get("content_classification")
        if not isinstance(classification, dict):
            continue
        storage_account = str(acct.get("name") or classification.get("account") or "")
        acct_ref = account_ref or (f"{provider}:{acct.get('subscription_id')}" if acct.get("subscription_id") else None)
        findings.extend(
            _blob_container_findings(
                classification,
                storage_account=storage_account,
                provider=provider,
                account_ref=acct_ref,
                region=region,
                environment=environment,
            )
        )

    return _dedupe(findings)
