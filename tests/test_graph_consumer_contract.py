"""Independent public-shape consumer against authenticated non-empty graph routes."""

import httpx
import pytest

from scripts.qualify_graph_consumer import ContractError, qualify, validate_base_url
from tests.test_graph_tenant_scope_and_bounds import _container_graph, _path_graph, api  # noqa: F401


class Consumer:
    def __init__(self, fixture, edit=None, headers=None):
        self.client, self.store, tenant_headers = fixture
        self.headers = tenant_headers["tenant-a"] if headers is None else headers
        self.edit = edit
        self.pages = 0

    def get(self, path, params=None):
        if path == "graph":
            self.pages += 1
        response = self.client.get("/v1/" + path, params=params, headers=self.headers)
        if self.edit:
            return self.edit(path, response, self.pages)
        return response


def test_consumer_preserves_scoped_identity_provenance_and_boundary_edges(api):  # noqa: F811
    report = qualify(Consumer(api), page_size=1, max_pages=3)
    assert report["status"] == "passed"
    assert report["nodes"] == 2 and report["relationships"] == 1
    assert report["node_pages_exhausted"] is True
    assert report["collection_coverage"] == "unknown"
    assert report["execution"] == "not_established"
    assert report["scope"]["tenant_id"] == "tenant-a"
    assert len(report["pages"]) == 2
    assert all(page["sha256"] and page["response"]["completeness"] for page in report["pages"])


def test_consumer_declares_its_own_page_bound(api):  # noqa: F811
    report = qualify(Consumer(api), page_size=1, max_pages=1)
    assert report["nodes"] == 1
    assert report["node_pages_exhausted"] is False


@pytest.mark.parametrize("parent_first", [False, True])
def test_consumer_reconciles_context_before_and_after_its_ranked_page(api, parent_first):  # noqa: F811
    graph = _container_graph("tenant-a", 3)
    for node in graph.nodes.values():
        node.risk_score = 10.0 if (node.id == "account:root") == parent_first else 0.0
    api[1].save_graph(graph)

    report = qualify(Consumer(api), page_size=1, max_pages=4)
    assert report["nodes"] == 4 and report["relationships"] == 3
    assert report["node_pages_exhausted"] is True
    assert len(report["pages"]) == 4
    assert sum(page["response"]["completeness"]["context_nodes"] for page in report["pages"]) == 3
    first = report["pages"][0]["response"]
    assert (first["nodes"][0]["id"] == "account:root") == parent_first
    assert all(page["response"]["completeness"]["ranked"] == 1 for page in report["pages"])


def test_consumer_context_does_not_exhaust_a_bounded_ranked_page(api):  # noqa: F811
    graph = _container_graph("tenant-a", 3)
    graph.nodes["res:00000"].risk_score = 10.0
    api[1].save_graph(graph)
    report = qualify(Consumer(api), page_size=1, max_pages=1)
    assert report["nodes"] == 2 and report["relationships"] == 1
    assert report["node_pages_exhausted"] is False


@pytest.mark.parametrize("field,value", [("label", "changed"), ("canonical_id", "changed"), ("future_field", {"changed": True})])
def test_consumer_rejects_changed_repeated_context_evidence(api, field, value):  # noqa: F811
    graph = _container_graph("tenant-a", 3)
    graph.nodes["account:root"].risk_score = 10.0
    api[1].save_graph(graph)

    def change(path, response, pages):
        body = response.json()
        if path == "graph" and pages == 2:
            next(node for node in body["nodes"] if node["id"] == "account:root")[field] = value
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match="Node evidence changed"):
        qualify(Consumer(api, change), page_size=1, max_pages=4)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ranked", None),
        ("ranked", True),
        ("ranked", -1),
        ("ranked", 1.0),
        ("context_nodes", None),
        ("context_nodes", True),
        ("context_nodes", -1),
        ("context_nodes", 1),
        ("returned", 0),
        ("returned", True),
    ],
)
def test_consumer_rejects_invalid_page_accounting(api, field, value):  # noqa: F811
    def change(path, response, pages):
        body = response.json()
        if path == "graph":
            body["completeness"][field] = value
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match="page accounting"):
        qualify(Consumer(api, change), page_size=1)


def test_consumer_still_rejects_oversized_ranked_pages(api):  # noqa: F811
    class Oversized(Consumer):
        def get(self, path, params=None):
            return super().get(path, params | {"limit": 2} if path == "graph" else params)

    with pytest.raises(ContractError, match="node-page bound"):
        qualify(Oversized(api), page_size=1)


def test_consumer_rejects_repeated_ranked_nodes_even_with_identical_evidence(api):  # noqa: F811
    first = None

    def repeat(path, response, pages):
        nonlocal first
        body = response.json()
        if path == "graph":
            if pages == 1:
                first = body["nodes"][0]
            else:
                body["nodes"][0] = first
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match="Ranked node repeated"):
        qualify(Consumer(api, repeat), page_size=1)


def test_consumer_rejects_duplicate_node_within_page(api):  # noqa: F811
    def duplicate(path, response, pages):
        body = response.json()
        if path == "graph":
            body["nodes"].append(body["nodes"][0].copy())
            body["completeness"].update(context_nodes=1, returned=2)
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match="Node repeated within"):
        qualify(Consumer(api, duplicate), page_size=1)


def test_consumer_rejects_empty_ranked_continuation(api):  # noqa: F811
    def empty(path, response, pages):
        body = response.json()
        if path == "graph":
            body["nodes"] = []
            body["completeness"].update(ranked=0, context_nodes=0, returned=0)
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match="Empty ranked page"):
        qualify(Consumer(api, empty), page_size=1)


def test_consumer_fails_closed_when_snapshot_is_replaced(api):  # noqa: F811
    def replace(path, response, pages):
        if path == "graph" and pages == 1:
            api[1].save_graph(_path_graph("tenant-a"))
        return response

    with pytest.raises(ContractError, match="409"):
        qualify(Consumer(api, replace), page_size=1)


@pytest.mark.parametrize("field", ["tenant_id", "scan_id", "snapshot_generation"])
def test_consumer_rejects_mixed_scope_even_on_200(api, field):  # noqa: F811
    def change(path, response, pages):
        body = response.json()
        if path == "graph" and pages == 2:
            body[field] = "different"
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match="scope or revision"):
        qualify(Consumer(api, change), page_size=1)


def test_consumer_rejects_unsupported_major_version(api):  # noqa: F811
    def change(path, response, pages):
        body = response.json()
        if path == "graph/schema":
            body["interchange"]["envelope"] = "agent-bom.graph/v2"
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match="Unsupported graph envelope"):
        qualify(Consumer(api, change))


def test_consumer_rejects_anonymous_request(api):  # noqa: F811
    with pytest.raises(ContractError, match="401"):
        qualify(Consumer(api, headers={}))


@pytest.mark.parametrize(
    "url", ["http://public.example", "https://user:password@example.test", "https://example.test?token=secret", "file:///tmp/graph"]
)
def test_remote_transport_and_credentials_are_explicit(url):
    with pytest.raises(ContractError):
        validate_base_url(url)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("entity_type", "future_kind", "Unknown entity"),
        ("canonical_id", "", "stable node identity"),
        ("evidence_provenance", {}, "versioned node provenance"),
    ],
)
def test_consumer_does_not_silently_drop_uninterpretable_evidence(api, field, value, message):  # noqa: F811
    def change(path, response, pages):
        body = response.json()
        if path == "graph":
            body["nodes"][0][field] = value
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match=message):
        qualify(Consumer(api, change))


def test_consumer_retains_unknown_optional_fields(api):  # noqa: F811
    def change(path, response, pages):
        body = response.json()
        if path == "graph":
            body["nodes"][0]["future_optional_evidence"] = {"source": "retained"}
        return httpx.Response(response.status_code, json=body)

    report = qualify(Consumer(api, change))
    assert report["pages"][0]["response"]["nodes"][0]["future_optional_evidence"] == {"source": "retained"}


def test_consumer_rejects_missing_completeness_instead_of_claiming_coverage(api):  # noqa: F811
    def change(path, response, pages):
        body = response.json()
        if path == "graph":
            body["completeness"] = {}
        return httpx.Response(response.status_code, json=body)

    with pytest.raises(ContractError, match="completeness"):
        qualify(Consumer(api, change))
