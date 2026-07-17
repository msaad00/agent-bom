from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Iterable

import pytest

from agent_bom.cloud import gcp_authorization_collector
from agent_bom.cloud.authorization_evidence import EvidenceSourceState
from agent_bom.cloud.gcp_authorization_collector import collect_gcp_authorization


class _Pager:
    def __init__(self, *pages: list[Any]) -> None:
        self.pages = pages
        self.pages_read = 0

    def __iter__(self):
        for page in self.pages:
            self.pages_read += 1
            yield from page


def _condition(expression: str) -> Any:
    return SimpleNamespace(expression=expression, title="restricted", description="test condition", location="")


def _binding(role: str, members: list[str], condition: Any = None) -> Any:
    return SimpleNamespace(role=role, members=members, condition=condition)


def _policy(*bindings: Any) -> Any:
    return SimpleNamespace(version=3, etag=b"etag", bindings=list(bindings))


def _asset(name: str, role: str = "roles/storage.objectViewer") -> Any:
    return SimpleNamespace(
        name=name,
        asset_type="storage.googleapis.com/Bucket",
        ancestors=["projects/123", "folders/10", "organizations/20"],
        iam_policy=_policy(_binding(role, ["serviceAccount:ci@proj-1.iam.gserviceaccount.com"])),
    )


class _AssetClient:
    def __init__(self, values: Iterable[Any]) -> None:
        self.values = values
        self.requests: list[dict[str, Any]] = []

    def list_assets(self, request: dict[str, Any]) -> Iterable[Any]:
        self.requests.append(request)
        return self.values


class _ProjectsClient:
    def __init__(self) -> None:
        self.policy = _policy(
            _binding(
                "roles/viewer",
                ["serviceAccount:ci@proj-1.iam.gserviceaccount.com"],
                _condition("resource.name.startsWith('projects/proj-1')"),
            )
        )

    def get_project(self, request: dict[str, Any]) -> Any:
        return SimpleNamespace(name="projects/123", project_id="proj-1", parent="folders/10")

    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        assert request["options"]["requested_policy_version"] == 3
        return self.policy


class _FoldersClient:
    def get_folder(self, request: dict[str, Any]) -> Any:
        return SimpleNamespace(name="folders/10", parent="organizations/20")

    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        return _policy()


class _OrganizationsClient:
    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        return _policy()


class _RolesClient:
    def get_role(self, request: dict[str, Any]) -> Any:
        name = request["name"]
        permissions = [f"test.permissions.{index}" for index in range(600)] if name == "roles/viewer" else ["storage.objects.get"]
        return SimpleNamespace(
            name=name,
            title=name,
            description="role",
            stage="GA",
            deleted=False,
            included_permissions=permissions,
        )


class _DisabledRolesClient(_RolesClient):
    def get_role(self, request: dict[str, Any]) -> Any:
        role = super().get_role(request)
        role.stage = "DISABLED"
        return role


class _DenyClient:
    def list_policies(self, request: dict[str, Any]) -> Iterable[Any]:
        if "projects%2Fproj-1" not in request["parent"]:
            return []
        rule = SimpleNamespace(
            denied_principals=["principal://iam.googleapis.com/projects/-/serviceAccounts/ci@proj-1.iam.gserviceaccount.com"],
            exception_principals=[],
            denied_permissions=["storage.googleapis.com/buckets.delete"],
            exception_permissions=[],
            denial_condition=_condition("resource.name.endsWith('/private')"),
        )
        return [SimpleNamespace(name="policies/project/denypolicies/protect", uid="deny-1", display_name="protect", rules=[rule])]


class _PabClient:
    def __init__(self, values: Iterable[Any] = ()) -> None:
        self.values = values

    def list_principal_access_boundary_policies(self, request: dict[str, Any]) -> Iterable[Any]:
        return self.values


class _PolicyBindingsClient:
    def __init__(self, values: Iterable[Any] = ()) -> None:
        self.values = values

    def list_policy_bindings(self, request: dict[str, Any]) -> Iterable[Any]:
        return self.values


def _clients(*, assets: Iterable[Any] | None = None, pabs: Iterable[Any] = (), pab_bindings: Iterable[Any] = ()) -> Any:
    return SimpleNamespace(
        assets=_AssetClient(assets if assets is not None else [_asset("//storage.googleapis.com/projects/_/buckets/data")]),
        projects=_ProjectsClient(),
        folders=_FoldersClient(),
        organizations=_OrganizationsClient(),
        roles=_RolesClient(),
        denies=_DenyClient(),
        pabs=_PabClient(pabs),
        policy_bindings=_PolicyBindingsClient(pab_bindings),
    )


def _source_states(result: dict[str, Any]) -> dict[str, str]:
    return {source["name"]: source["state"] for source in result["iam_sources"]}


def test_collects_v3_allow_roles_hierarchy_and_deny_without_permission_truncation() -> None:
    result = collect_gcp_authorization(None, "proj-1", clients=_clients(), warnings=[], missing=[])

    assert _source_states(result) == {
        "allow_policies": EvidenceSourceState.COMPLETE.value,
        "deny_policies": EvidenceSourceState.COMPLETE.value,
        "principal_access_boundaries": EvidenceSourceState.COMPLETE.value,
        "resource_hierarchy": EvidenceSourceState.COMPLETE.value,
        "role_definitions": EvidenceSourceState.COMPLETE.value,
    }
    assert result["iam_hierarchy"] == ["projects/proj-1", "folders/10", "organizations/20"]
    conditional = next(policy for policy in result["allow_policies"] if policy["resource"] == "projects/proj-1")
    assert conditional["version"] == 3
    assert conditional["bindings"][0]["condition"]["expression"].startswith("resource.name")
    viewer = next(role for role in result["role_definitions"] if role["id"] == "roles/viewer")
    assert len(viewer["permissions"]) == 600
    assert result["deny_policies"][0]["rules"][0]["condition"]["expression"].endswith("'/private')")
    assert result["iam_scope"] == "projects/123"


def test_disabled_role_is_retained_as_non_authorizing_evidence() -> None:
    clients = _clients()
    clients.roles = _DisabledRolesClient()

    result = collect_gcp_authorization(None, "proj-1", clients=clients, warnings=[])

    assert {role["completeness"] for role in result["role_definitions"]} == {EvidenceSourceState.UNAVAILABLE.value}
    assert all(role["permissions"] == [] for role in result["role_definitions"])


def test_malformed_deny_rule_downgrades_deny_source() -> None:
    clients = _clients()
    malformed = SimpleNamespace(
        name="policies/project/denypolicies/malformed",
        uid="deny-bad",
        display_name="malformed",
        rules=[SimpleNamespace(deny_rule=SimpleNamespace(denied_principals=[], denied_permissions=[]))],
    )
    clients.denies.list_policies = lambda request: [malformed]

    result = collect_gcp_authorization(None, "proj-1", clients=clients, warnings=[])

    assert _source_states(result)["deny_policies"] == EvidenceSourceState.PARTIAL.value
    source = next(item for item in result["iam_sources"] if item["name"] == "deny_policies")
    assert "dropped 1 malformed deny rule" in source["diagnostics"]


def test_asset_pager_is_consumed_across_pages() -> None:
    pager = _Pager([_asset("//storage.googleapis.com/buckets/one")], [_asset("//storage.googleapis.com/buckets/two")])
    result = collect_gcp_authorization(None, "proj-1", clients=_clients(assets=pager), warnings=[])

    assert pager.pages_read == 2
    assert {policy["resource"] for policy in result["allow_policies"]} >= {
        "//storage.googleapis.com/buckets/one",
        "//storage.googleapis.com/buckets/two",
    }


def test_cap_marks_allow_and_role_sources_truncated() -> None:
    result = collect_gcp_authorization(
        None,
        "proj-1",
        clients=_clients(assets=[_asset("//storage.googleapis.com/buckets/one"), _asset("//storage.googleapis.com/buckets/two")]),
        warnings=[],
        max_records=1,
    )

    assert _source_states(result)["allow_policies"] == EvidenceSourceState.TRUNCATED.value
    assert _source_states(result)["role_definitions"] == EvidenceSourceState.TRUNCATED.value


def test_malformed_allow_binding_marks_allow_and_role_sources_partial() -> None:
    malformed = _asset("//storage.googleapis.com/buckets/bad")
    malformed.iam_policy = _policy(_binding("", ["serviceAccount:ci@proj-1.iam.gserviceaccount.com"]))

    result = collect_gcp_authorization(None, "proj-1", clients=_clients(assets=[malformed]), warnings=[])

    assert _source_states(result)["allow_policies"] == EvidenceSourceState.PARTIAL.value
    assert _source_states(result)["role_definitions"] == EvidenceSourceState.PARTIAL.value


class _DeniedError(Exception):
    code = 403


@pytest.mark.parametrize(
    ("client_name", "method_name", "permission", "source"),
    [
        ("assets", "list_assets", "cloudasset.assets.listIamPolicy", "allow_policies"),
        ("roles", "get_role", "iam.roles.get", "role_definitions"),
        ("denies", "list_policies", "iam.denypolicies.list", "deny_policies"),
        ("pabs", "list_principal_access_boundary_policies", "iam.principalaccessboundarypolicies.list", "principal_access_boundaries"),
        ("policy_bindings", "list_policy_bindings", "iam.policybindings.list", "principal_access_boundaries"),
    ],
)
def test_access_denied_is_explicit(
    client_name: str,
    method_name: str,
    permission: str,
    source: str,
) -> None:
    clients = _clients()

    def denied(*args: Any, **kwargs: Any) -> Any:
        raise _DeniedError("permission denied")

    setattr(getattr(clients, client_name), method_name, denied)
    missing: list[dict[str, str]] = []
    result = collect_gcp_authorization(None, "proj-1", clients=clients, warnings=[], missing=missing)

    assert _source_states(result)[source] == EvidenceSourceState.ACCESS_DENIED.value
    assert any(item["permission"] == permission for item in missing)


def test_missing_role_definition_marks_role_source_partial() -> None:
    clients = _clients()

    def missing(*args: Any, **kwargs: Any) -> Any:
        raise LookupError("role no longer exists")

    clients.roles.get_role = missing
    result = collect_gcp_authorization(None, "proj-1", clients=clients, warnings=[], missing=[])

    assert _source_states(result)["allow_policies"] == EvidenceSourceState.COMPLETE.value
    assert _source_states(result)["role_definitions"] == EvidenceSourceState.PARTIAL.value
    role_source = next(source for source in result["iam_sources"] if source["name"] == "role_definitions")
    assert role_source["diagnostics"] == [
        "unresolved role definition: roles/storage.objectViewer",
        "unresolved role definition: roles/viewer",
    ]


def test_hierarchy_access_denied_marks_hierarchy_and_allow_incomplete() -> None:
    clients = _clients()

    def denied(*args: Any, **kwargs: Any) -> Any:
        raise _DeniedError("permission denied")

    clients.projects.get_project = denied
    result = collect_gcp_authorization(None, "proj-1", clients=clients, warnings=[], missing=[])

    assert _source_states(result)["resource_hierarchy"] == EvidenceSourceState.ACCESS_DENIED.value
    assert _source_states(result)["allow_policies"] == EvidenceSourceState.ACCESS_DENIED.value
    assert _source_states(result)["deny_policies"] == EvidenceSourceState.ACCESS_DENIED.value
    assert _source_states(result)["principal_access_boundaries"] == EvidenceSourceState.ACCESS_DENIED.value


def test_missing_sdk_sets_every_required_source_explicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_sdk(credentials: Any) -> Any:
        raise ImportError("google-cloud-asset missing")

    monkeypatch.setattr(gcp_authorization_collector, "_load_clients", missing_sdk)
    result = collect_gcp_authorization(None, "proj-1", warnings=[])

    assert set(_source_states(result).values()) == {EvidenceSourceState.SDK_MISSING.value}


def test_nonempty_pab_is_preserved_but_source_stays_partial_until_evaluated() -> None:
    pab = SimpleNamespace(
        name="organizations/20/locations/global/principalAccessBoundaryPolicies/restrict",
        uid="pab-1",
        display_name="restrict",
        details=SimpleNamespace(
            enforcement_version="1",
            rules=[
                SimpleNamespace(description="prod only", resources=["//cloudresourcemanager.googleapis.com/projects/123"], effect="ALLOW")
            ],
        ),
    )
    binding = SimpleNamespace(
        name="projects/proj-1/locations/global/policyBindings/restrict",
        uid="binding-1",
        target=SimpleNamespace(principal_set="//cloudresourcemanager.googleapis.com/projects/123"),
        policy_kind="PRINCIPAL_ACCESS_BOUNDARY",
        policy=pab.name,
        policy_uid="pab-1",
        condition=_condition("principal.type == 'iam.googleapis.com/ServiceAccount'"),
    )

    result = collect_gcp_authorization(
        None,
        "proj-1",
        clients=_clients(pabs=[pab], pab_bindings=[binding]),
        warnings=[],
    )

    assert _source_states(result)["principal_access_boundaries"] == EvidenceSourceState.PARTIAL.value
    assert result["pab_policies"][0]["rules"][0]["resources"] == ["//cloudresourcemanager.googleapis.com/projects/123"]
    assert result["pab_bindings"][0]["condition"]["expression"].startswith("principal.type")
