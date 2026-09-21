"""Structural qualifiers for findings retained across incomplete collections."""

from enum import Enum


class FindingObservationStatus(str, Enum):
    OBSERVED = "observed"
    UNRECONFIRMED = "unreconfirmed"


class ReconfirmationReason(str, Enum):
    SCAN_PARTIAL = "scan_partial"
    SCAN_FAILED = "scan_failed"
    SCAN_NOT_EXECUTED = "scan_not_executed"
    SCOPE_PARTIAL = "scope_partial"
    SCOPE_PERMISSION_DENIED = "scope_permission_denied"
    SCOPE_UNAVAILABLE = "scope_unavailable"
    SCOPE_UNSUPPORTED = "scope_unsupported"
    SCOPE_SKIPPED = "scope_skipped"
    SCOPE_INCOMPLETE = "scope_incomplete"
    COVERAGE_ISSUE = "coverage_issue"
