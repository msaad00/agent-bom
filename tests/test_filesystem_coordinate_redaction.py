"""Filesystem occurrence coordinates must join without leaking host paths."""

import json

from agent_bom.security import sanitize_sensitive_payload


def test_embedded_filesystem_coordinate_is_private_and_consistent():
    value = "fs:/home/audit_customer/private_repository"
    payload = {"affected_servers": [value], "id": "server:" + value, "source": "server:" + value, "name": value}
    cleaned = sanitize_sensitive_payload(payload)
    assert "/home/audit_customer" not in json.dumps(cleaned)
    assert cleaned["id"] == cleaned["source"]
    assert cleaned["id"] == "server:" + cleaned["affected_servers"][0]
    assert sanitize_sensitive_payload(cleaned) == cleaned
    other = sanitize_sensitive_payload({"name": "fs:/different/private_repository"})
    assert other["name"] != cleaned["name"]


def test_package_and_localhost_paths_are_not_filesystem_coordinates():
    payload = {"purl": "pkg:golang/github.com/example/module@1.0.0", "message": "Cannot connect to localhost/internal IPs: localhost"}
    assert sanitize_sensitive_payload(payload) == payload


def test_scan_progress_does_not_persist_private_paths():
    from agent_bom.api.models import ScanJob, ScanRequest
    from agent_bom.api.pipeline import ScanPipeline

    job = ScanJob(job_id="progress-test", created_at="2026-10-06T00:00:00Z", request=ScanRequest())
    ScanPipeline(job).update_step("discovery", "Scanning filesystem: /home/customer/private_project")
    assert "/home/customer" not in job.progress[0]
    assert "Scanning filesystem:" in job.progress[0]


def test_legacy_progress_projection_redacts_paths_but_preserves_relative_context():
    messages = [
        "Discovering MCP configs in /home/customer/private_project...",
        "Scanning Terraform: C:\\Users\\customer\\private_project",
        "VEX applied: 2 suppressed from /home/customer/private.json",
    ]
    for message in messages:
        cleaned = sanitize_sensitive_payload({"message": message})["message"]
        assert "customer" not in cleaned
    assert sanitize_sensitive_payload({"message": "Scanning Terraform: infra/main.tf"})["message"].endswith("infra/main.tf")
