"""Read-only Kubernetes API transports for live posture collection.

The native transport is intentionally small: it authenticates with the mounted
service-account token and CA, permits only Kubernetes API GETs, and bounds list
pagination.  ``kubectl`` remains a workstation fallback for configured local
contexts; it is not required by the in-cluster path.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import ssl
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from agent_bom.security import sanitize_error, sanitize_text

DEFAULT_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
DEFAULT_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
MAX_TIMEOUT_SECONDS = 60
MAX_TOKEN_BYTES = 64 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
KUBELET_HTTPS_PORT = 10_250


class K8sTransportError(Exception):
    """A secret-safe Kubernetes read failure."""

    def __init__(self, message: str, *, status_code: int | None = None, reason: str = "request_failed") -> None:
        super().__init__(sanitize_text(sanitize_error(message), max_len=200))
        self.status_code = status_code
        self.reason = reason


@dataclass(frozen=True)
class K8sReadResult:
    """One bounded Kubernetes list result."""

    data: dict[str, Any]
    object_count: int
    pages: int
    truncated: bool


class K8sReadTransport(Protocol):
    """Transport boundary used by the posture collector."""

    name: str

    def list_resource(
        self,
        resource: str,
        *,
        namespace: str | None = None,
        all_namespaces: bool = False,
    ) -> K8sReadResult: ...

    def get_kubelet_json(
        self,
        host: str,
        port: int,
        path: str,
        *,
        timeout: int | None = None,
    ) -> dict[str, Any]: ...

    def close(self) -> None: ...


def _bounded_positive(name: str, value: int, maximum: int) -> int:
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


def _clean_host(host: str) -> str:
    clean_host = host.strip()
    if not clean_host or any(part in clean_host for part in ("/", "://", "@", "?", "#", " ", "\t", "\n")):
        raise K8sTransportError("Invalid Kubernetes service host", reason="invalid_host")
    return clean_host


def _base_url(host: str, port: int) -> str:
    clean_host = _clean_host(host)
    try:
        clean_port = _bounded_positive("port", int(port), 65_535)
    except (TypeError, ValueError) as exc:
        raise K8sTransportError("Invalid Kubernetes service port", reason="configuration") from exc
    display_host = f"[{clean_host}]" if ":" in clean_host else clean_host
    return f"https://{display_host}:{clean_port}"


def validate_kubelet_endpoint(host: str, port: int) -> tuple[str, int]:
    """Return a private InternalIP kubelet endpoint on its standard HTTPS port."""
    clean_host = _clean_host(host)
    try:
        address = ipaddress.ip_address(clean_host)
    except ValueError as exc:
        raise K8sTransportError("Kubelet endpoint must be an internal IP address", reason="invalid_endpoint") from exc
    if (
        not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise K8sTransportError("Kubelet endpoint must be an internal IP address", reason="invalid_endpoint")
    if isinstance(port, bool) or port != KUBELET_HTTPS_PORT:
        raise K8sTransportError("Kubelet endpoint must use the configured HTTPS port", reason="invalid_endpoint")
    return clean_host, port


def _read_http_response(response: httpx.Response, *, source: str, max_bytes: int) -> bytearray:
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            declared_length = 0
        if declared_length > max_bytes:
            raise K8sTransportError(f"{source} exceeded the configured byte bound", reason="response_too_large")

    body = bytearray()
    for chunk in response.iter_bytes():
        if len(body) + len(chunk) > max_bytes:
            raise K8sTransportError(f"{source} exceeded the configured byte bound", reason="response_too_large")
        body.extend(chunk)
    return body


def _parse_json_object(body: str | bytes | bytearray, *, source: str) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise K8sTransportError(f"{source} returned invalid JSON", reason="invalid_json") from exc
    if not isinstance(payload, dict):
        raise K8sTransportError(f"{source} returned a non-object response", reason="invalid_json")
    return payload


def _resource_path(resource: str, namespace: str | None, all_namespaces: bool) -> str:
    namespaced = {
        "pods": ("/api/v1", "pods"),
        "networkpolicies": ("/apis/networking.k8s.io/v1", "networkpolicies"),
        "roles": ("/apis/rbac.authorization.k8s.io/v1", "roles"),
    }
    cluster_scoped = {
        "clusterrolebindings": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "clusterroles": "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        "nodes": "/api/v1/nodes",
    }
    if resource in cluster_scoped:
        return cluster_scoped[resource]
    if resource not in namespaced:
        raise K8sTransportError("Unsupported Kubernetes resource", reason="invalid_resource")
    prefix, plural = namespaced[resource]
    if all_namespaces:
        return f"{prefix}/{plural}"
    if not namespace:
        raise K8sTransportError("Namespace is required for this Kubernetes resource", reason="invalid_namespace")
    return f"{prefix}/namespaces/{quote(namespace, safe='')}/{plural}"


class InClusterK8sTransport:
    """Native HTTPS transport authenticated by a mounted service account."""

    name = "in-cluster"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        token_path: Path = DEFAULT_TOKEN_PATH,
        ca_path: Path = DEFAULT_CA_PATH,
        timeout: int = 15,
        page_size: int = 500,
        max_pages: int = 20,
        max_items: int = 10_000,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._timeout = _bounded_positive("timeout", timeout, MAX_TIMEOUT_SECONDS)
        self._page_size = _bounded_positive("page_size", page_size, 1_000)
        self._max_pages = _bounded_positive("max_pages", max_pages, 100)
        self._max_items = _bounded_positive("max_items", max_items, 50_000)
        self._max_response_bytes = _bounded_positive("max_response_bytes", max_response_bytes, MAX_RESPONSE_BYTES)
        base_url = _base_url(host, port)

        try:
            if token_path.stat().st_size > MAX_TOKEN_BYTES:
                raise K8sTransportError("Service-account token is too large", reason="invalid_credentials")
            token = token_path.read_text(encoding="utf-8").strip()
        except K8sTransportError:
            raise
        except (OSError, UnicodeError) as exc:
            raise K8sTransportError(f"Unable to read service-account token: {sanitize_error(exc)}", reason="credentials")
        if not token:
            raise K8sTransportError("Service-account token is empty", reason="invalid_credentials")
        if not ca_path.is_file():
            raise K8sTransportError("Service-account CA is unavailable", reason="credentials")

        # A custom transport is used only by deterministic tests. Production
        # clients always verify the mounted cluster CA.
        try:
            self._verify: ssl.SSLContext | bool = False if http_transport is not None else ssl.create_default_context(cafile=str(ca_path))
            self._headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            self._http_transport = http_transport
            self._client = httpx.Client(
                base_url=base_url,
                headers=self._headers,
                timeout=self._timeout,
                verify=self._verify,
                transport=http_transport,
                follow_redirects=False,
            )
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise K8sTransportError(f"Unable to initialize Kubernetes TLS: {sanitize_error(exc)}", reason="tls") from exc

    def close(self) -> None:
        self._client.close()

    def _request_json(
        self,
        path: str,
        *,
        params: Mapping[str, str | int] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        request_timeout = self._timeout if timeout is None else _bounded_positive("timeout", timeout, MAX_TIMEOUT_SECONDS)
        try:
            with self._client.stream("GET", path, params=params, timeout=request_timeout) as response:
                if not 200 <= response.status_code < 300:
                    reason = "forbidden" if response.status_code in {401, 403} else "not_found" if response.status_code == 404 else "http"
                    raise K8sTransportError(
                        f"Kubernetes API returned HTTP {response.status_code}",
                        status_code=response.status_code,
                        reason=reason,
                    )
                body = _read_http_response(
                    response,
                    source="Kubernetes API response",
                    max_bytes=self._max_response_bytes,
                )
        except K8sTransportError:
            raise
        except httpx.TimeoutException as exc:
            raise K8sTransportError(f"Kubernetes API request timed out: {sanitize_error(exc)}", reason="timeout") from exc
        except httpx.HTTPError as exc:
            raise K8sTransportError(f"Kubernetes API request failed: {sanitize_error(exc)}", reason="connection") from exc
        return _parse_json_object(body, source="Kubernetes API")

    def get_kubelet_json(
        self,
        host: str,
        port: int,
        path: str,
        *,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Read one explicitly allowed kubelet endpoint without API proxying."""
        if path != "/configz":
            raise K8sTransportError("Kubelet API path is not permitted", reason="invalid_path")
        kubelet_host, kubelet_port = validate_kubelet_endpoint(host, port)
        request_timeout = self._timeout if timeout is None else _bounded_positive("timeout", timeout, MAX_TIMEOUT_SECONDS)
        try:
            with (
                httpx.Client(
                    base_url=_base_url(kubelet_host, kubelet_port),
                    headers=self._headers,
                    timeout=request_timeout,
                    verify=self._verify,
                    transport=self._http_transport,
                    follow_redirects=False,
                ) as client,
                client.stream("GET", path, timeout=request_timeout) as response,
            ):
                if not 200 <= response.status_code < 300:
                    reason = "forbidden" if response.status_code in {401, 403} else "not_found" if response.status_code == 404 else "http"
                    raise K8sTransportError(
                        f"Kubelet API returned HTTP {response.status_code}",
                        status_code=response.status_code,
                        reason=reason,
                    )
                body = _read_http_response(
                    response,
                    source="Kubelet API response",
                    max_bytes=self._max_response_bytes,
                )
        except K8sTransportError:
            raise
        except httpx.TimeoutException as exc:
            raise K8sTransportError(f"Kubelet API request timed out: {sanitize_error(exc)}", reason="timeout") from exc
        except httpx.HTTPError as exc:
            raise K8sTransportError(f"Kubelet API request failed: {sanitize_error(exc)}", reason="connection") from exc
        return _parse_json_object(body, source="Kubelet API")

    def _list_json(self, path: str, *, params: Mapping[str, str | int] | None = None) -> K8sReadResult:
        items: list[Any] = []
        continue_token = ""
        seen_tokens: set[str] = set()
        pages = 0
        truncated = False
        final_payload: dict[str, Any] = {}

        while pages < self._max_pages and len(items) < self._max_items:
            page_params: dict[str, str | int] = dict(params or {})
            page_params["limit"] = min(self._page_size, self._max_items - len(items))
            if continue_token:
                page_params["continue"] = continue_token
            payload = self._request_json(path, params=page_params)
            page_items = payload.get("items", [])
            if not isinstance(page_items, list):
                raise K8sTransportError("Kubernetes list response has invalid items", reason="invalid_json")
            remaining = self._max_items - len(items)
            items.extend(page_items[:remaining])
            if len(page_items) > remaining:
                truncated = True
            pages += 1
            final_payload = payload
            metadata = payload.get("metadata", {})
            if not isinstance(metadata, dict):
                raise K8sTransportError("Kubernetes list response has invalid metadata", reason="invalid_json")
            next_token = metadata.get("continue", "")
            if not isinstance(next_token, str):
                raise K8sTransportError("Kubernetes list response has invalid pagination", reason="invalid_json")
            if not next_token:
                break
            if next_token in seen_tokens:
                raise K8sTransportError("Kubernetes pagination token repeated", reason="pagination")
            seen_tokens.add(next_token)
            continue_token = next_token
        else:
            truncated = bool(continue_token)

        metadata = final_payload.get("metadata", {})
        if isinstance(metadata, dict) and metadata.get("continue") and (pages >= self._max_pages or len(items) >= self._max_items):
            truncated = True
        result_payload = dict(final_payload)
        result_payload["items"] = items
        result_metadata = dict(metadata) if isinstance(metadata, dict) else {}
        result_metadata.pop("continue", None)
        result_payload["metadata"] = result_metadata
        return K8sReadResult(data=result_payload, object_count=len(items), pages=pages, truncated=truncated)

    def list_resource(
        self,
        resource: str,
        *,
        namespace: str | None = None,
        all_namespaces: bool = False,
    ) -> K8sReadResult:
        return self._list_json(_resource_path(resource, namespace, all_namespaces))


RunJson = Callable[[list[str], int], dict[str, Any]]


class KubectlK8sTransport:
    """Bounded workstation fallback using a configured kubectl context."""

    name = "kubectl"

    def __init__(
        self,
        *,
        context: str | None = None,
        run_json: RunJson | None = None,
        timeout: int = 60,
        page_size: int = 500,
        max_items: int = 10_000,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.context = context
        self._run_json = run_json or self._default_run_json
        self._timeout = _bounded_positive("timeout", timeout, MAX_TIMEOUT_SECONDS)
        self._page_size = _bounded_positive("page_size", page_size, 1_000)
        self._max_items = _bounded_positive("max_items", max_items, 50_000)
        self._max_response_bytes = _bounded_positive("max_response_bytes", max_response_bytes, MAX_RESPONSE_BYTES)

    def close(self) -> None:
        return None

    def _default_run_json(self, args: list[str], timeout: int) -> dict[str, Any]:
        if shutil.which("kubectl") is None:
            raise K8sTransportError("kubectl is not available", reason="unavailable")
        command = ["kubectl", *args]
        if self.context:
            command += ["--context", self.context]
        try:
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                result = subprocess.run(
                    command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    text=False,
                    timeout=timeout,
                )
                stdout_file.seek(0, os.SEEK_END)
                stdout_size = stdout_file.tell()
                stdout_file.seek(0)
                stderr_file.seek(0)
                result_stdout = getattr(result, "stdout", None)
                result_stderr = getattr(result, "stderr", None)
                stdout = result_stdout if isinstance(result_stdout, (str, bytes)) else stdout_file.read(self._max_response_bytes + 1)
                stderr = result_stderr if isinstance(result_stderr, (str, bytes)) else stderr_file.read(64 * 1024)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            reason = "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "unavailable"
            raise K8sTransportError(f"kubectl request failed: {sanitize_error(exc)}", reason=reason) from exc
        if stdout_size > self._max_response_bytes or len(stdout.encode() if isinstance(stdout, str) else stdout) > self._max_response_bytes:
            raise K8sTransportError("kubectl response exceeded the configured byte bound", reason="response_too_large")
        stderr_text = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr
        if result.returncode != 0:
            safe_stderr = sanitize_text(sanitize_error(stderr_text.strip()), max_len=160)
            lowered = stderr_text.lower()
            status_code = 403 if "forbidden" in lowered else 401 if "unauthorized" in lowered else 404 if "not found" in lowered else None
            raise K8sTransportError(
                f"kubectl returned exit code {result.returncode}: {safe_stderr}",
                status_code=status_code,
                reason="kubectl",
            )
        return _parse_json_object(stdout, source="kubectl")

    def list_resource(
        self,
        resource: str,
        *,
        namespace: str | None = None,
        all_namespaces: bool = False,
    ) -> K8sReadResult:
        # Validate the resource against the same allowlist as the native path.
        _resource_path(resource, namespace, all_namespaces)
        args = ["get", resource, "-o", "json", f"--chunk-size={self._page_size}"]
        if resource in {"pods", "networkpolicies", "roles"}:
            if all_namespaces:
                args.append("-A")
            elif namespace:
                args += ["-n", namespace]
        payload = self._run_json(args, self._timeout)
        raw_items = payload.get("items", [])
        if not isinstance(raw_items, list):
            raise K8sTransportError("kubectl list response has invalid items", reason="invalid_json")
        truncated = len(raw_items) > self._max_items
        items = raw_items[: self._max_items]
        data = dict(payload)
        data["items"] = items
        return K8sReadResult(data=data, object_count=len(items), pages=1, truncated=truncated)

    def get_kubelet_json(
        self,
        host: str,
        port: int,
        path: str,
        *,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        del host, port, path, timeout
        raise K8sTransportError(
            "Direct kubelet config collection is unavailable through the kubectl fallback",
            status_code=404,
            reason="unsupported",
        )


def select_k8s_transport(
    *,
    context: str | None = None,
    token_path: Path = DEFAULT_TOKEN_PATH,
    ca_path: Path = DEFAULT_CA_PATH,
    run_json: RunJson | None = None,
    page_size: int = 500,
    max_pages: int = 20,
    max_items: int = 10_000,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> K8sReadTransport:
    """Choose native in-cluster HTTPS or the kubectl workstation fallback.

    An explicit context always selects kubectl.  Otherwise, any in-cluster
    service environment marker selects the native path and configuration
    failures are surfaced; they never silently fall back to kubectl.
    """

    host = os.getenv("KUBERNETES_SERVICE_HOST")
    port_text = os.getenv("KUBERNETES_SERVICE_PORT")
    if context is None and (host or port_text):
        if not host or not port_text:
            raise K8sTransportError("Incomplete in-cluster Kubernetes service configuration", reason="configuration")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise K8sTransportError("Invalid Kubernetes service port", reason="configuration") from exc
        return InClusterK8sTransport(
            host=host,
            port=port,
            token_path=token_path,
            ca_path=ca_path,
            page_size=page_size,
            max_pages=max_pages,
            max_items=max_items,
            max_response_bytes=max_response_bytes,
        )
    return KubectlK8sTransport(
        context=context,
        run_json=run_json,
        page_size=page_size,
        max_items=max_items,
        max_response_bytes=max_response_bytes,
    )


__all__ = [
    "DEFAULT_CA_PATH",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TOKEN_PATH",
    "InClusterK8sTransport",
    "K8sReadResult",
    "K8sReadTransport",
    "K8sTransportError",
    "KUBELET_HTTPS_PORT",
    "KubectlK8sTransport",
    "select_k8s_transport",
    "validate_kubelet_endpoint",
]
