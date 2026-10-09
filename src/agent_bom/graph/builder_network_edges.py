"""Cloud network-edge inventory projection (gateways, peering, load balancers)."""

from __future__ import annotations

# Generic network-edge collections promoted as CLOUD_RESOURCE inventory nodes.
# (payload key, cloud service, resource_type, resource_kind, label, id field)
# Load balancers are intentionally NOT here: AWS uses ``elb_load_balancers`` and
# Azure routes them through the normalized-resource path; only GCP's new
# ``load_balancers`` key is ingested here, gated to GCP below.
_NETWORK_EDGE_COLLECTIONS: tuple[tuple[str, str, str, str, str, str], ...] = (
    ("nat_gateways", "network", "nat_gateway", "nat-gateway", "nat gateway", "id"),
    ("internet_gateways", "network", "internet_gateway", "internet-gateway", "internet gateway", "id"),
    ("vpc_endpoints", "network", "vpc_endpoint", "vpc-endpoint", "vpc endpoint", "id"),
    ("route_tables", "network", "route_table", "route-table", "route table", "id"),
    ("network_acls", "network", "network_acl", "network-acl", "network acl", "id"),
)


_GCP_LB_COLLECTION: tuple[str, str, str, str, str, str] = (
    "load_balancers",
    "network",
    "load_balancer",
    "load-balancer",
    "load balancer",
    "id",
)
