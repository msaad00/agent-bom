from __future__ import annotations

from agent_bom.deploy_k8s_cleanup import CleanupOperation, build_cleanup_operations, execute_cleanup


def test_build_cleanup_operations_orders_external_secret_then_generated_secret_cleanup():
    ops = build_cleanup_operations(
        namespace="agent-bom",
        label_selector="app.kubernetes.io/name=agent-bom,app.kubernetes.io/managed-by=Helm",
        target_secrets=["agent-bom-control-plane"],
    )
    assert ops[0] == CleanupOperation(
        kind="ExternalSecret",
        target="collection",
        api_path="/apis/external-secrets.io/v1beta1/namespaces/agent-bom/externalsecrets",
        label_selector="app.kubernetes.io/name=agent-bom,app.kubernetes.io/managed-by=Helm",
    )
    assert ops[1] == CleanupOperation(
        kind="Secret",
        target="named",
        api_path="/api/v1/namespaces/agent-bom/secrets/agent-bom-control-plane",
        name="agent-bom-control-plane",
    )
    assert ops[-1].kind == "PersistentVolumeClaim"


def test_execute_cleanup_treats_missing_resources_as_success(monkeypatch):
    monkeypatch.setattr(
        "agent_bom.deploy_k8s_cleanup._request",
        lambda method, path, query=None: (404, '{"message":"not found"}'),
    )
    failed = execute_cleanup(
        [
            CleanupOperation(
                kind="Secret",
                target="named",
                api_path="/api/v1/namespaces/agent-bom/secrets/example",
                name="example",
            )
        ]
    )
    assert failed == 0


def test_execute_cleanup_reports_non_404_failures(monkeypatch):
    monkeypatch.setattr(
        "agent_bom.deploy_k8s_cleanup._request",
        lambda method, path, query=None: (500, '{"message":"boom"}'),
    )
    failed = execute_cleanup(
        [
            CleanupOperation(
                kind="Job",
                target="collection",
                api_path="/apis/batch/v1/namespaces/agent-bom/jobs",
                label_selector="app.kubernetes.io/name=agent-bom",
            )
        ]
    )
    assert failed == 1
