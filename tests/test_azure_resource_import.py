"""Regression guard: import ResourceManagementClient from the stable submodule.

``azure-mgmt-resource`` 26.x removed the top-level ``ResourceManagementClient``
re-export, so ``from azure.mgmt.resource import ResourceManagementClient`` raises
ImportError on a current install (breaking AI Foundry discovery and any
resource-graph-dependent CIS check). ``azure.mgmt.resource.resources`` has carried
the class across the whole pinned range (>=23.0); this test fails if a future
re-export change or a regression reintroduces the fragile top-level import.
"""

from __future__ import annotations

import pytest

pytest.importorskip("azure.mgmt.resource", reason="azure-mgmt-resource not installed")


def test_resource_management_client_importable_from_submodule():
    from azure.mgmt.resource.resources import ResourceManagementClient

    assert ResourceManagementClient is not None


def test_azure_module_uses_submodule_import_not_toplevel():
    """The azure.py source must not reintroduce the fragile top-level import."""
    from pathlib import Path

    import agent_bom.cloud.azure as azure_mod

    source = Path(azure_mod.__file__).read_text()
    assert "from azure.mgmt.resource.resources import ResourceManagementClient" in source
    assert "from azure.mgmt.resource import ResourceManagementClient" not in source
