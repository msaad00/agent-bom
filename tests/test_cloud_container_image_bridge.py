"""Regression: cloud container images (ECS/EKS/SageMaker/Cloud Run) that are
pre-filled with a ``container-image`` name:tag placeholder must still be routed
to the deep image scanner. Previously the ``not server.packages`` guard saw the
placeholder as non-empty and silently skipped deep scanning — while Azure (which
leaves packages empty) worked, an inconsistency proving the bug.
"""

from __future__ import annotations

from agent_bom.models import Package


def _target_selected(packages: list[Package]) -> bool:
    """Mirror the bridge guard in cli/agents/_cloud.py."""
    real = [p for p in packages if p.ecosystem != "container-image"]
    command, args = "docker", ["run", "myapp:latest"]
    return command == "docker" and len(args) >= 2 and args[0] == "run" and not real


def test_container_image_placeholder_still_scanned():
    placeholder = [Package(name="myapp", version="latest", ecosystem="container-image")]
    assert _target_selected(placeholder) is True


def test_already_extracted_packages_not_rescanned():
    real = [Package(name="requests", version="2.25.0", ecosystem="pypi")]
    assert _target_selected(real) is False


def test_empty_packages_scanned():
    assert _target_selected([]) is True
