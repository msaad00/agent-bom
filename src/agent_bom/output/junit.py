"""JUnit XML output for CI/CD integration (Jenkins, GitLab CI, Azure DevOps).

Each vulnerability maps to a JUnit test case:
- Test suite = ecosystem
- Test case  = CVE ID + package
- Failure    = CRITICAL or HIGH severity
- Error      = MEDIUM severity
- Skipped    = LOW or UNKNOWN severity (informational)
"""

from __future__ import annotations

from xml.etree.ElementTree import Element, SubElement, indent, tostring

from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.finding import Finding
from agent_bom.models import AIBOMReport, BlastRadius, Severity
from agent_bom.output.finding_views import (
    cve_findings,
    evidence,
    has_high_or_critical,
    is_medium,
    package_ecosystem,
    package_name,
    package_version,
    severity_value,
)


def to_junit(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> str:
    """Convert an AIBOMReport to JUnit XML string."""
    findings = cve_findings(report, blast_radii)
    scan_run = effective_scan_run(report)
    incomplete_without_findings = scan_run.outcome is not ScanOutcome.COMPLETE and not findings

    testsuites = Element("testsuites")
    testsuites.set("name", "agent-bom")
    testsuites.set("tests", str(len(findings) + int(incomplete_without_findings)))
    testsuites.set("failures", str(sum(1 for finding in findings if has_high_or_critical(finding))))
    testsuites.set("errors", str(sum(1 for finding in findings if is_medium(finding)) + int(incomplete_without_findings)))
    testsuites.set("time", "0")

    # Group by ecosystem
    eco_map: dict[str, list[Finding]] = {}
    for finding in findings:
        eco = package_ecosystem(finding) or "unknown"
        eco_map.setdefault(eco, []).append(finding)

    for eco, eco_findings in sorted(eco_map.items()):
        suite = SubElement(testsuites, "testsuite")
        suite.set("name", eco)
        suite.set("tests", str(len(eco_findings)))
        suite.set("failures", str(sum(1 for finding in eco_findings if has_high_or_critical(finding))))
        suite.set("errors", str(sum(1 for finding in eco_findings if is_medium(finding))))
        suite.set("time", "0")

        for finding in eco_findings:
            pkg_name = package_name(finding)
            pkg_version = package_version(finding)
            vuln_id = finding.cve_id or finding.id
            sev = severity_value(finding)
            summary = finding.description or vuln_id
            tc = SubElement(suite, "testcase")
            tc.set("classname", f"{eco}.{pkg_name}")
            tc.set("name", f"{vuln_id} ({pkg_name}@{pkg_version})")
            tc.set("time", "0")

            detail = _build_detail(finding)

            if sev in (Severity.CRITICAL.value, Severity.HIGH.value):
                fail = SubElement(tc, "failure")
                fail.set("message", f"{sev.upper()}: {summary}")
                fail.set("type", sev)
                fail.text = detail
            elif sev == Severity.MEDIUM.value:
                err = SubElement(tc, "error")
                err.set("message", f"MEDIUM: {summary}")
                err.set("type", "medium")
                err.text = detail
            else:
                skipped = SubElement(tc, "skipped")
                skipped.set("message", f"{sev.upper()}: {summary}")
                skipped.text = detail

    if incomplete_without_findings:
        suite = SubElement(testsuites, "testsuite")
        suite.set("name", "scan-execution")
        suite.set("tests", "1")
        suite.set("failures", "0")
        suite.set("errors", "1")
        suite.set("time", "0")
        testcase = SubElement(suite, "testcase", classname="agent-bom.scan", name=f"scan {scan_run.outcome.value}", time="0")
        error = SubElement(testcase, "error", type="scan_execution")
        error.set("message", f"Scan {scan_run.outcome.value}: incomplete evidence")
        error.text = "\n".join(f"{issue.source}: {issue.message}" for issue in scan_run.issues)

    indent(testsuites, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(testsuites, encoding="unicode")


def _build_detail(finding: Finding) -> str:
    """Build detail text for a JUnit test case."""
    vuln_id = finding.cve_id or finding.id
    lines = [
        f"CVE: {vuln_id}",
        f"Package: {package_name(finding)}@{package_version(finding)}",
        f"Ecosystem: {package_ecosystem(finding) or 'unknown'}",
        f"Severity: {severity_value(finding)}",
    ]
    if finding.cvss_score is not None:
        lines.append(f"CVSS: {finding.cvss_score}")
    if finding.epss_score is not None:
        lines.append(f"EPSS: {finding.epss_score:.4f}")
    if finding.fixed_version:
        lines.append(f"Fix: {finding.fixed_version}")
    if finding.cwe_ids:
        lines.append(f"CWE: {', '.join(finding.cwe_ids)}")
    if finding.affected_agents:
        lines.append(f"Affected agents: {', '.join(finding.affected_agents)}")
    if finding.exposed_credentials:
        lines.append(f"Exposed credentials: {len(finding.exposed_credentials)}")
    if evidence(finding, "published_at", ""):
        lines.append(f"Published: {evidence(finding, 'published_at')}")
    if finding.description:
        lines.append(f"Summary: {finding.description}")
    return "\n".join(lines)


def export_junit(report: AIBOMReport, output_path: str, blast_radii: list[BlastRadius] | None = None) -> None:
    """Write JUnit XML report to file."""
    from pathlib import Path

    Path(output_path).write_text(to_junit(report, blast_radii), encoding="utf-8")
