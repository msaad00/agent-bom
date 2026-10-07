"""Repository locations are captured where the scan root is known."""

from dataclasses import asdict

from agent_bom.finding import iac_finding_to_finding
from agent_bom.iac import scan_iac_with_context


def test_iac_relative_source_survives_finding_projection(tmp_path):
    directory = tmp_path / "deploy"
    directory.mkdir()
    (directory / "Dockerfile").write_text("FROM ubuntu:latest\nRUN apt-get update\n")
    findings = scan_iac_with_context(tmp_path).findings
    assert findings
    for native in findings:
        assert native.repository_relative_path == "deploy/Dockerfile"
        finding = iac_finding_to_finding(asdict(native))
        assert finding.evidence["repository_relative_path"] == "deploy/Dockerfile"
