"""Data models for IaC misconfiguration findings."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IaCFinding:
    """A single IaC misconfiguration finding."""

    rule_id: str  # e.g. "DOCKER-001", "K8S-001", "TF-SEC-001"
    severity: str  # critical, high, medium, low
    title: str  # Short description
    message: str  # Detailed explanation with fix guidance
    file_path: str  # Relative path to the file
    line_number: int  # Line where the issue was found
    category: str  # "dockerfile", "kubernetes", "terraform"
    compliance: list[str] = field(default_factory=list)  # e.g. ["CIS-5.1", "NIST-CM-6"]
    attack_techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs, e.g. ["T1552.001"]
    atlas_techniques: list[str] = field(default_factory=list)  # MITRE ATLAS IDs, e.g. ["AML.T0010"]
    remediation: str = ""  # Fix guidance


@dataclass
class ScanContext:
    """Deployment and authorization context for an IaC scan.

    Controls which scanners are authorised to run (``enabled_scanners``) and
    records the deployment mode so callers can adapt output accordingly.

    Two orthogonal gates are applied in ``scan_iac_with_context`` for each
    scanner:

    1. **Authorization** — is the scanner in ``enabled_scanners``?
       ``None`` means all scanners are unlocked (default).
       A non-empty frozenset is an explicit allowlist; scanners absent from it
       are locked out and emit a ``"disabled"`` verdict.

    2. **Applicability** — did the scanner match any files during the walk?
       Zero files matched → ``"not-applicable"``; one or more → ``"ran"``.

    Deployment modes
    ----------------
    ``"standalone"``
        Full agent-bom install (bare-metal, Docker, Kubernetes, CI/CD).
        All scanners unlocked by default.
    ``"native-app"``
        Running inside a Snowflake Native App (SPCS).
        Bare-metal / OS-level scanners will emit ``not-applicable`` naturally
        because there are no matching files; no special handling required.
    ``"github-action"``
        Running as the agent-bom GitHub Action.
        Same scanner set as standalone; context surfaces in SARIF output.
    ``"mcp"``
        Invoked via the MCP tool interface.
        Context is passed by the MCP client in tool arguments.
    """

    deployment_mode: str = "standalone"
    enabled_scanners: frozenset[str] | None = None  # None = all unlocked


@dataclass
class ScannerVerdict:
    """Capability verdict for a single scanner after a scan run.

    Statuses
    --------
    ``"ran"``
        Scanner was authorised, found at least one target file, and executed.
    ``"not-applicable"``
        Scanner was authorised but found zero matching files in the scan root.
        This is the expected status for scanners whose file types don't exist
        in the scanned directory (e.g. Dockerfile scanner on a pure-Terraform
        repo, or bare-metal scanners inside a Snowflake Native App).
    ``"disabled"``
        Scanner was explicitly locked out via ``ScanContext.enabled_scanners``.
        No files were inspected.
    """

    scanner_id: str
    status: str  # "ran" | "not-applicable" | "disabled"
    files_scanned: int = 0
    reason: str = ""  # human-readable; populated for not-applicable + disabled


@dataclass
class ScanResult:
    """Complete result of a context-aware IaC scan.

    ``findings`` is identical in content to the list returned by the legacy
    ``scan_iac_directory`` function.  ``verdicts`` is the per-scanner
    capability table — one entry per known scanner regardless of whether it
    ran, giving callers a transparent record of what was and was not checked.
    """

    findings: list[IaCFinding] = field(default_factory=list)
    verdicts: list[ScannerVerdict] = field(default_factory=list)
