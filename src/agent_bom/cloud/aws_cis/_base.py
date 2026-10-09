"""Shared models, client helpers and read-coverage contract for the CIS AWS benchmark."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("agent_bom.cloud.aws_cis_benchmark")

_AWS_RETRY_CONFIG = {"max_attempts": 5, "mode": "adaptive"}


def _aws_client_config() -> Any | None:
    """Return the bounded adaptive retry policy when botocore is available."""
    try:
        from botocore.config import Config
    except ImportError:
        return None
    # Botocore may normalize the retry mapping in place when it prepares a
    # client. Give every client an independent mapping so one normalization
    # cannot contaminate the module template or later clients.
    return Config(retries=dict(_AWS_RETRY_CONFIG))


def _safe_error_evidence(prefix: str, error_code: str) -> str:
    """Build client-safe evidence text without leaking raw exception details."""
    if error_code:
        return f"{prefix} (AWS error code: {error_code})"
    return prefix


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NO_DATA = "no_data"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class CISCheckResult:
    """Result of a single CIS AWS Foundations Benchmark check."""

    check_id: str
    title: str
    status: CheckStatus
    severity: str
    evidence: str = ""
    resource_ids: list[str] = field(default_factory=list)
    recommendation: str = ""
    cis_section: str = ""
    # Boundary attribution for multi-account / multi-subscription / multi-project
    # fan-out. Holds the AWS account id, Azure subscription id, or GCP project id
    # the check ran against. Empty for a single-boundary run. Lets an aggregated
    # report keep per-boundary provenance on every finding.
    account_id: str = ""
    # Structured network exposure (open ports/CIDR to the internet) so the graph
    # can model port-level reachability instead of keyword-matching evidence text.
    # Each entry: {"resource": str, "from_port": int, "to_port": int,
    # "protocol": str, "scope": "internet"}.
    network_exposure: list[dict] = field(default_factory=list)
    # Structured remediation (issue #665). Populated by
    # ``agent_bom.cloud.cis_remediation.attach_remediation(result, cloud=...)``
    # so per-check functions stay thin. Schema defined in that module.
    remediation: dict = field(default_factory=dict)


@dataclass
class CISBenchmarkReport:
    """Aggregated CIS AWS Foundations Benchmark results."""

    benchmark_version: str = "3.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    region: str = ""
    account_id: str = ""
    # Populated only by the multi-account fan-out: the member accounts actually
    # evaluated and any per-account warnings (e.g. an account skipped because the
    # read-only role could not be assumed). Empty on a single-account run.
    accounts_scanned: list[str] = field(default_factory=list)
    regions_scanned: list[str] = field(default_factory=list)
    # Estate-scope truth. A selected-region benchmark is inherently partial for
    # regional CIS controls; only an enabled-region fan-out may claim complete.
    completeness: str = "partial"
    scope: str = "selected-region"
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def errored(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.ERROR)

    @property
    def not_applicable(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.NOT_APPLICABLE)

    @property
    def no_data(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.NO_DATA)

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.evaluated * 100) if self.evaluated else 0.0

    def to_dict(self) -> dict:
        from agent_bom.cloud.benchmark_manifests import benchmark_manifest
        from agent_bom.mitre_attack import tag_cis_check

        return {
            "benchmark": "CIS AWS Foundations",
            "benchmark_version": self.benchmark_version,
            "benchmark_manifest": benchmark_manifest("aws"),
            "account_id": self.account_id,
            "accounts_scanned": self.accounts_scanned,
            "regions_scanned": self.regions_scanned,
            "completeness": self.completeness,
            "scope": self.scope,
            "region": self.region,
            "pass_rate": round(self.pass_rate, 1),
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "no_data": self.no_data,
            "not_applicable": self.not_applicable,
            "evaluated": self.evaluated,
            "total": self.total,
            "warnings": self.warnings,
            "checks": [
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "status": c.status.value,
                    "severity": c.severity,
                    "evidence": c.evidence,
                    "resource_ids": c.resource_ids,
                    "recommendation": c.recommendation,
                    "remediation": c.remediation,
                    "cis_section": c.cis_section,
                    "account_id": c.account_id,
                    "network_exposure": c.network_exposure,
                    "attack_techniques": tag_cis_check(c),
                }
                for c in self.checks
            ],
        }


def finalize_read_coverage(
    result: CISCheckResult,
    *,
    inspected: int,
    denied: list,
    permission: str,
    resource_kind: str,
    pass_evidence: str,
    unavailable: dict[str, list[str]] | None = None,
) -> CISCheckResult:
    """Finalize per-resource read coverage without erasing known failures.

    Strict GRC contract: any permission denial on a listed resource means the
    full scope cannot be certified compliant. PASS only when every listed
    resource was read successfully and at least one resource was evaluated.
    Known failures remain FAIL while retaining explicit partial coverage.
    Unavailable reads carry a bounded cause label, never raw provider errors.

    Decision table (``denied`` is the list of resources whose read was denied):
      * ``denied`` non-empty  -> ERROR (names missing permission + coverage);
      * ``denied`` empty and ``inspected`` zero -> NO_DATA (never PASS);
      * ``denied`` empty and resources inspected -> PASS with ``pass_evidence``.
    """
    prior_failure = result.status == CheckStatus.FAIL
    prior_evidence, prior_resources = result.evidence, list(result.resource_ids)
    unavailable = {cause: resources for cause, resources in (unavailable or {}).items() if resources}
    unavailable_count = sum(len(resources) for resources in unavailable.values())
    denied_count = len(denied)
    if unavailable_count:
        total = inspected + denied_count + unavailable_count
        causes = [f"{cause}: {len(resources)}" for cause, resources in sorted(unavailable.items())]
        if denied_count:
            causes.append(f"permission denied: {denied_count}")
        result.status = CheckStatus.ERROR
        result.evidence = (
            f"Incomplete evaluation: read {inspected}/{total} {resource_kind}(s); "
            f"unread resources ({'; '.join(causes)}). Compliance is unknown for skipped resources."
        )
        if "billing_disabled" in unavailable:
            result.evidence += " Restore project billing before retrying."
        if "service_disabled" in unavailable:
            result.evidence += " Enable the required project API before retrying."
        if denied_count:
            result.evidence += f" Grant '{permission}' for resources with permission denied."
        result.resource_ids = [*denied, *(resource for resources in unavailable.values() for resource in resources)][:20]
    elif denied_count:
        result.status = CheckStatus.ERROR
        if inspected == 0:
            result.evidence = (
                f"Could not read {denied_count} {resource_kind}(s) — permission denied on every one "
                f"(0 inspected). Grant '{permission}' so this check can be evaluated; "
                "reporting PASS here would be a false compliant."
            )
        else:
            total = inspected + denied_count
            result.evidence = (
                f"Incomplete evaluation: read {inspected}/{total} {resource_kind}(s); "
                f"{denied_count} could not be read (permission denied). "
                f"Grant '{permission}' for full coverage — PASS not reported; "
                "compliance is unknown for skipped resources."
            )
        result.resource_ids = list(denied)[:20]
    elif inspected == 0:
        result.status = CheckStatus.NO_DATA
        result.evidence = f"No {resource_kind}(s) were discovered; this check has no data and cannot report PASS."
    else:
        result.status = CheckStatus.PASS
        result.evidence = pass_evidence
    if prior_failure:
        result.status = CheckStatus.FAIL
        result.evidence = prior_evidence + (" " + result.evidence if denied_count or unavailable_count else "")
        result.resource_ids = prior_resources
    return result
