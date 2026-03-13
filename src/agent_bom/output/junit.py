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

from agent_bom.models import AIBOMReport, BlastRadius, Severity


def to_junit(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> str:
    """Convert an AIBOMReport to JUnit XML string."""
    brs = blast_radii or report.blast_radii

    testsuites = Element("testsuites")
    testsuites.set("name", "agent-bom")
    testsuites.set("tests", str(len(brs)))
    testsuites.set("failures", str(sum(1 for br in brs if br.vulnerability.severity in (Severity.CRITICAL, Severity.HIGH))))
    testsuites.set("errors", str(sum(1 for br in brs if br.vulnerability.severity == Severity.MEDIUM)))
    testsuites.set("time", "0")

    # Group by ecosystem
    eco_map: dict[str, list[BlastRadius]] = {}
    for br in brs:
        eco = br.package.ecosystem or "unknown"
        eco_map.setdefault(eco, []).append(br)

    for eco, eco_brs in sorted(eco_map.items()):
        suite = SubElement(testsuites, "testsuite")
        suite.set("name", eco)
        suite.set("tests", str(len(eco_brs)))
        suite.set("failures", str(sum(1 for br in eco_brs if br.vulnerability.severity in (Severity.CRITICAL, Severity.HIGH))))
        suite.set("errors", str(sum(1 for br in eco_brs if br.vulnerability.severity == Severity.MEDIUM)))
        suite.set("time", "0")

        for br in eco_brs:
            v = br.vulnerability
            tc = SubElement(suite, "testcase")
            tc.set("classname", f"{eco}.{br.package.name}")
            tc.set("name", f"{v.id} ({br.package.name}@{br.package.version})")
            tc.set("time", "0")

            sev = v.severity
            detail = _build_detail(br)

            if sev in (Severity.CRITICAL, Severity.HIGH):
                fail = SubElement(tc, "failure")
                fail.set("message", f"{sev.value.upper()}: {v.summary or v.id}")
                fail.set("type", sev.value)
                fail.text = detail
            elif sev == Severity.MEDIUM:
                err = SubElement(tc, "error")
                err.set("message", f"MEDIUM: {v.summary or v.id}")
                err.set("type", "medium")
                err.text = detail
            else:
                skipped = SubElement(tc, "skipped")
                skipped.set("message", f"{sev.value.upper()}: {v.summary or v.id}")
                skipped.text = detail

    indent(testsuites, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(testsuites, encoding="unicode")


def _build_detail(br: BlastRadius) -> str:
    """Build detail text for a JUnit test case."""
    v = br.vulnerability
    lines = [
        f"CVE: {v.id}",
        f"Package: {br.package.name}@{br.package.version}",
        f"Ecosystem: {br.package.ecosystem or 'unknown'}",
        f"Severity: {v.severity.value}",
    ]
    if v.cvss_score is not None:
        lines.append(f"CVSS: {v.cvss_score}")
    if v.epss_score is not None:
        lines.append(f"EPSS: {v.epss_score:.4f}")
    if v.fixed_version:
        lines.append(f"Fix: {v.fixed_version}")
    if v.cwe_ids:
        lines.append(f"CWE: {', '.join(v.cwe_ids)}")
    if br.affected_agents:
        lines.append(f"Affected agents: {', '.join(a.name for a in br.affected_agents)}")
    if br.exposed_credentials:
        lines.append(f"Exposed credentials: {len(br.exposed_credentials)}")
    if v.summary:
        lines.append(f"Summary: {v.summary}")
    return "\n".join(lines)


def export_junit(report: AIBOMReport, output_path: str, blast_radii: list[BlastRadius] | None = None) -> None:
    """Write JUnit XML report to file."""
    from pathlib import Path

    Path(output_path).write_text(to_junit(report, blast_radii), encoding="utf-8")
