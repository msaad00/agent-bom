from __future__ import annotations

import json
import ssl
from pathlib import Path
from types import SimpleNamespace

import certifi
import httpx
import pytest

from agent_bom.k8s_transport import (
    InClusterK8sTransport,
    K8sTransportError,
    KubectlK8sTransport,
    select_k8s_transport,
)


def _service_account_files(tmp_path: Path) -> tuple[Path, Path]:
    token_path = tmp_path / "token"
    ca_path = tmp_path / "ca.crt"
    token_path.write_text("service-account-secret\n", encoding="utf-8")
    ca_path.write_text(Path(certifi.where()).read_text(encoding="utf-8"), encoding="utf-8")
    return token_path, ca_path


def test_native_transport_paginates_with_bearer_auth_and_bounds(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer service-account-secret"
        if request.url.params.get("continue"):
            return httpx.Response(200, json={"items": [{"metadata": {"name": "pod-c"}}], "metadata": {}})
        return httpx.Response(
            200,
            json={
                "items": [{"metadata": {"name": "pod-a"}}, {"metadata": {"name": "pod-b"}}],
                "metadata": {"continue": "next-page"},
            },
        )

    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        page_size=2,
        max_pages=3,
        max_items=5,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        result = transport.list_resource("pods", all_namespaces=True)
    finally:
        transport.close()

    assert [item["metadata"]["name"] for item in result.data["items"]] == ["pod-a", "pod-b", "pod-c"]
    assert result.object_count == 3
    assert result.pages == 2
    assert result.truncated is False
    assert requests[0].url.params["limit"] == "2"
    assert requests[1].url.params["continue"] == "next-page"


def test_native_transport_marks_page_limit_truncation(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        page = request.url.params.get("continue") or "0"
        return httpx.Response(
            200,
            json={"items": [{"metadata": {"name": f"pod-{page}"}}], "metadata": {"continue": str(int(page) + 1)}},
        )

    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        page_size=1,
        max_pages=2,
        max_items=10,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        result = transport.list_resource("pods", all_namespaces=True)
    finally:
        transport.close()

    assert result.pages == 2
    assert result.object_count == 2
    assert result.truncated is True


def test_native_transport_sanitizes_forbidden_response(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="token=service-account-secret /var/run/secrets/private")

    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(K8sTransportError) as caught:
            transport.list_resource("pods", all_namespaces=True)
    finally:
        transport.close()

    assert caught.value.status_code == 403
    assert "service-account-secret" not in str(caught.value)
    assert "/var/run" not in str(caught.value)


def test_native_transport_bounds_timeout_and_sanitizes_timeout_detail(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("token=service-account-secret https://10.0.0.1/private", request=request)

    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        timeout=5,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(K8sTransportError) as caught:
            transport.list_resource("pods", all_namespaces=True)
    finally:
        transport.close()

    assert caught.value.reason == "timeout"
    assert "service-account-secret" not in str(caught.value)
    assert "10.0.0.1" not in str(caught.value)


def test_native_transport_rejects_unbounded_timeout(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    with pytest.raises(ValueError, match="timeout"):
        InClusterK8sTransport(
            host="10.0.0.1",
            port=443,
            token_path=token_path,
            ca_path=ca_path,
            timeout=61,
        )


def test_native_transport_rejects_proxy_paths(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        http_transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
    )
    try:
        with pytest.raises(K8sTransportError, match="not permitted"):
            transport.get_kubelet_json("10.0.0.10", 10250, "/proxy/configz")
    finally:
        transport.close()


def test_native_transport_rejects_external_or_nonstandard_kubelet_endpoints(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    requests: list[httpx.Request] = []
    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        http_transport=httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(200, json={})),
    )
    try:
        with pytest.raises(K8sTransportError, match="internal"):
            transport.get_kubelet_json("8.8.8.8", 10250, "/configz")
        with pytest.raises(K8sTransportError, match="port"):
            transport.get_kubelet_json("10.0.0.10", 443, "/configz")
    finally:
        transport.close()

    assert requests == []


def test_native_transport_reads_only_direct_kubelet_configz(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "10.0.0.10"
        assert request.url.port == 10250
        assert request.url.path == "/configz"
        assert request.headers["authorization"] == "Bearer service-account-secret"
        return httpx.Response(200, json={"kubeletconfig": {"readOnlyPort": 0}})

    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        result = transport.get_kubelet_json("10.0.0.10", 10250, "/configz")
    finally:
        transport.close()

    assert result == {"kubeletconfig": {"readOnlyPort": 0}}


def test_custom_http_transport_never_disables_certificate_validation(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        http_transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
    )
    try:
        assert isinstance(transport._verify, ssl.SSLContext)
        assert transport._verify.verify_mode is ssl.CERT_REQUIRED
        assert transport._verify.check_hostname is True
    finally:
        transport.close()


def test_native_transport_rejects_response_before_json_materialization(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        max_response_bytes=32,
        http_transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=b'{"items":["' + (b"x" * 64) + b'"]}')),
    )
    try:
        with pytest.raises(K8sTransportError, match="configured byte bound") as caught:
            transport.list_resource("pods", all_namespaces=True)
    finally:
        transport.close()

    assert caught.value.reason == "response_too_large"


def test_native_transport_rejects_non_object_list_metadata(tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    transport = InClusterK8sTransport(
        host="10.0.0.1",
        port=443,
        token_path=token_path,
        ca_path=ca_path,
        http_transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json={"items": [{"metadata": {"name": "pod-a"}}], "metadata": "bad"})
        ),
    )
    try:
        with pytest.raises(K8sTransportError, match="metadata") as caught:
            transport.list_resource("pods", all_namespaces=True)
    finally:
        transport.close()

    assert caught.value.reason == "invalid_json"


def test_select_transport_prefers_in_cluster_and_never_falls_back_to_kubectl(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

    selected = select_k8s_transport(token_path=token_path, ca_path=ca_path)
    try:
        assert isinstance(selected, InClusterK8sTransport)
    finally:
        selected.close()


def test_select_transport_uses_kubectl_for_workstation_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.delenv("KUBERNETES_SERVICE_PORT", raising=False)
    selected = select_k8s_transport(context="dev-cluster")
    assert isinstance(selected, KubectlK8sTransport)
    assert selected.context == "dev-cluster"


def test_in_cluster_configuration_failure_never_falls_back_to_kubectl(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    missing_token = tmp_path / "missing-token"
    ca_path = tmp_path / "ca.crt"
    ca_path.write_text(Path(certifi.where()).read_text(encoding="utf-8"), encoding="utf-8")

    with pytest.raises(K8sTransportError, match="service-account token"):
        select_k8s_transport(token_path=missing_token, ca_path=ca_path)


def test_in_cluster_out_of_range_port_is_a_transport_configuration_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    token_path, ca_path = _service_account_files(tmp_path)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "0")

    with pytest.raises(K8sTransportError, match="service port") as caught:
        select_k8s_transport(token_path=token_path, ca_path=ca_path)

    assert caught.value.reason == "configuration"


def test_kubectl_transport_caps_returned_items() -> None:
    payload = {"items": [{"metadata": {"name": f"pod-{index}"}} for index in range(4)]}

    def run_json(args: list[str], timeout: int) -> dict:
        assert "--chunk-size=2" in args
        assert timeout <= 60
        return json.loads(json.dumps(payload))

    transport = KubectlK8sTransport(run_json=run_json, page_size=2, max_items=3)
    result = transport.list_resource("pods", namespace="prod")

    assert result.object_count == 3
    assert result.truncated is True


def test_kubectl_transport_classifies_and_sanitizes_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.k8s_transport as transport_module

    monkeypatch.setattr(transport_module.shutil, "which", lambda _command: "/usr/bin/kubectl")
    monkeypatch.setattr(
        transport_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Error from server (Forbidden): token=cluster-secret /var/run/private",
        ),
    )
    transport = KubectlK8sTransport()

    with pytest.raises(K8sTransportError) as caught:
        transport.list_resource("networkpolicies", namespace="prod")

    assert caught.value.status_code == 403
    assert "cluster-secret" not in str(caught.value)
    assert "/var/run" not in str(caught.value)


def test_kubectl_transport_rejects_stdout_above_byte_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.k8s_transport as transport_module

    def oversized_run(*_args, **kwargs):
        kwargs["stdout"].write(b'{"items":["' + (b"x" * 64) + b'"]}')
        return SimpleNamespace(returncode=0, stdout=None, stderr=None)

    monkeypatch.setattr(transport_module.shutil, "which", lambda _command: "/usr/bin/kubectl")
    monkeypatch.setattr(transport_module.subprocess, "run", oversized_run)
    transport = KubectlK8sTransport(max_response_bytes=32)

    with pytest.raises(K8sTransportError, match="configured byte bound") as caught:
        transport.list_resource("pods", namespace="prod")

    assert caught.value.reason == "response_too_large"
