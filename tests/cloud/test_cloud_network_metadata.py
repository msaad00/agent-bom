"""Network placement metadata is captured into the cloud-origin envelope.

Foundation for network-reachability analysis: AWS describe_instances already
returns subnet/VPC/security-group/IP, which the scanner previously dropped. This
captures the low-risk identifiers (no rules, no credentials) so downstream
overlays can reason about reachability.
"""

from __future__ import annotations

from agent_bom.cloud.aws import _aws_instance_network
from agent_bom.cloud.normalization import build_cloud_origin


def test_instance_network_extracts_placement_and_groups():
    instance = {
        "InstanceId": "i-123",
        "SubnetId": "subnet-abc",
        "VpcId": "vpc-xyz",
        "PublicIpAddress": "203.0.113.10",
        "PrivateIpAddress": "10.0.1.5",
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}],
    }
    net = _aws_instance_network(instance)
    assert net["subnet_id"] == "subnet-abc"
    assert net["vpc_id"] == "vpc-xyz"
    assert net["public_ip"] == "203.0.113.10"
    assert net["availability_zone"] == "us-east-1a"
    assert net["security_group_ids"] == ["sg-1", "sg-2"]


def test_instance_network_merges_eni_groups_and_dedupes():
    instance = {
        "SecurityGroups": [{"GroupId": "sg-1"}],
        "NetworkInterfaces": [{"Groups": [{"GroupId": "sg-1"}, {"GroupId": "sg-3"}]}],
    }
    assert _aws_instance_network(instance)["security_group_ids"] == ["sg-1", "sg-3"]


def test_instance_network_omits_empty_fields():
    # a private instance with no public IP / no VPC info
    net = _aws_instance_network({"PrivateIpAddress": "10.0.0.9"})
    assert net == {"private_ip": "10.0.0.9"}


def test_build_cloud_origin_includes_sanitized_network():
    origin = build_cloud_origin(
        provider="aws",
        service="ec2",
        resource_type="instance",
        resource_id="i-1",
        resource_name="prod-api",
        network={
            "subnet_id": "subnet-1",
            "vpc_id": "vpc-1",
            "public_ip": "198.51.100.7",
            "security_group_ids": ["sg-a", "sg-b"],
            "secret_field": "should-not-appear",  # only the known keys are kept
        },
    )
    net = origin["network"]
    assert net["subnet_id"] == "subnet-1"
    assert net["security_group_ids"] == ["sg-a", "sg-b"]
    assert "secret_field" not in net


def test_build_cloud_origin_without_network_has_no_network_key():
    origin = build_cloud_origin(provider="aws", service="ec2", resource_type="instance", resource_id="i-2", resource_name="x")
    assert "network" not in origin
