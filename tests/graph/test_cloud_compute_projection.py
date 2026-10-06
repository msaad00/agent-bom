"""Compute projection can be checked without running graph analysis overlays."""

from copy import deepcopy

import pytest

from agent_bom.graph.cloud_compute_projection import project_instances, project_security_groups
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import RelationshipType


@pytest.mark.parametrize("exposed", [True, False, None, "unknown"])
def test_compute_projection_preserves_scope_and_only_links_recorded_groups(exposed):
    inventory = {
        "security_groups": [None, {}, {"group_id": "sg-recorded", "internet_exposed": exposed}],
        "instances": [
            None,
            {},
            {
                "instance_id": "vm-recorded",
                "security_group_ids": ["sg-recorded", "sg-missing"],
                "tags": {"environment": "prod"},
            },
        ],
    }
    before = deepcopy(inventory)
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
    resource_ids = []
    groups = project_security_groups(
        graph,
        inventory,
        provider="aws",
        account_id="account-a",
        region="region-a",
        data_sources=["inventory-a"],
        resource_ids=resource_ids,
    )
    instances = project_instances(
        graph,
        inventory,
        provider="aws",
        account_id="account-a",
        region="region-a",
        data_sources=["inventory-a"],
        resource_ids=resource_ids,
        sg_node_by_id=groups,
    )

    assert len(instances) == 1
    instance_id, source_record = instances[0]
    assert source_record == before["instances"][2]
    assert inventory == before
    assert resource_ids == [groups["sg-recorded"], instance_id]
    assert set(graph.nodes) == set(resource_ids)
    instance = graph.nodes[instance_id]
    assert instance.attributes["account_id"] == "account-a"
    assert instance.attributes["location"] == "region-a"
    assert instance.dimensions.environment == "prod"
    assert instance.data_sources == ["inventory-a"]
    assert graph.tenant_id == "tenant-a"
    memberships = [edge for edge in graph.edges if edge.relationship == RelationshipType.PART_OF]
    assert [(edge.source, edge.target) for edge in memberships] == [(instance_id, groups["sg-recorded"])]
    exposures = [edge for edge in graph.edges if edge.relationship == RelationshipType.EXPOSED_TO]
    assert bool(exposures) is (exposed is True)
    assert all(edge.target == instance_id and edge.source == groups["sg-recorded"] for edge in exposures)
