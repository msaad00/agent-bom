"""Kubernetes mutating webhook for agent-bom proxy sidecar injection."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Callable

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agent_bom.api.audit_log import log_action


def _is_enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _is_disabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"0", "false", "no", "off", "disabled"}


@dataclass(frozen=True)
class SidecarInjectorSettings:
    proxy_image: str
    control_plane_url: str
    control_plane_token_secret_name: str
    control_plane_token_secret_key: str = "token"
    container_name: str = "agent-bom-proxy"
    tenant_label_key: str = "agent-bom.io/tenant"
    inject_label_key: str = "agent-bom.io/proxy"
    inject_annotation_key: str = "agent-bom.io/proxy"
    injected_annotation_key: str = "agent-bom.io/proxy-injected"
    mcp_url_annotation_key: str = "agent-bom.io/mcp-url"
    mcp_port_annotation_key: str = "agent-bom.io/mcp-port"
    policy_configmap_annotation_key: str = "agent-bom.io/proxy-policy-configmap"
    default_mcp_port: int = 3000
    metrics_port: int = 8422
    policy_refresh_seconds: int = 30
    audit_push_interval: int = 10
    detect_credentials: bool = True
    block_undeclared: bool = True
    policy_configmap_name: str | None = None
    audit_actor: str = "sidecar-injector"
    audit_logger: Callable[..., None] = log_action


def _patch_add(path: str, value: Any) -> dict[str, Any]:
    return {"op": "add", "path": path, "value": value}


def _coerce_port(value: str | None, default: int) -> int:
    try:
        port = int(value or default)
    except (TypeError, ValueError):
        return default
    return port if port > 0 else default


def _target_url(metadata: dict[str, Any], settings: SidecarInjectorSettings) -> str:
    annotations = metadata.get("annotations") or {}
    explicit = str(annotations.get(settings.mcp_url_annotation_key, "") or "").strip()
    if explicit:
        return explicit
    port = _coerce_port(annotations.get(settings.mcp_port_annotation_key), settings.default_mcp_port)
    return f"http://127.0.0.1:{port}"


def _already_injected(pod: dict[str, Any], settings: SidecarInjectorSettings) -> bool:
    containers = (pod.get("spec") or {}).get("containers") or []
    return any(container.get("name") == settings.container_name for container in containers)


def _should_inject(metadata: dict[str, Any], settings: SidecarInjectorSettings) -> bool:
    labels = metadata.get("labels") or {}
    annotations = metadata.get("annotations") or {}
    requested = labels.get(settings.inject_label_key) or annotations.get(settings.inject_annotation_key)
    if _is_disabled(requested):
        return False
    return True


def _sidecar_container(settings: SidecarInjectorSettings, metadata: dict[str, Any]) -> dict[str, Any]:
    policy_configmap = (
        str((metadata.get("annotations") or {}).get(settings.policy_configmap_annotation_key, "") or "").strip()
        or settings.policy_configmap_name
    )
    args = [
        "proxy",
        "--url",
        _target_url(metadata, settings),
        "--policy-refresh-seconds",
        str(settings.policy_refresh_seconds),
        "--audit-push-interval",
        str(settings.audit_push_interval),
        "--log",
        "/var/log/agent-bom/audit.jsonl",
    ]
    if policy_configmap:
        args.extend(["--policy", "/etc/agent-bom/policy.json"])
    if settings.detect_credentials:
        args.append("--detect-credentials")
    if settings.block_undeclared:
        args.append("--block-undeclared")
    mounts: list[dict[str, Any]] = [{"name": "agent-bom-audit-logs", "mountPath": "/var/log/agent-bom"}]
    if policy_configmap:
        mounts.append({"name": "agent-bom-proxy-policy", "mountPath": "/etc/agent-bom", "readOnly": True})
    return {
        "name": settings.container_name,
        "image": settings.proxy_image,
        "args": args,
        "env": [
            {"name": "AGENT_BOM_API_URL", "value": settings.control_plane_url},
            {
                "name": "AGENT_BOM_API_TOKEN",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": settings.control_plane_token_secret_name,
                        "key": settings.control_plane_token_secret_key,
                    }
                },
            },
        ],
        "ports": [{"containerPort": settings.metrics_port, "name": "metrics", "protocol": "TCP"}],
        "volumeMounts": mounts,
        "resources": {
            "requests": {"cpu": "50m", "memory": "64Mi"},
            "limits": {"cpu": "500m", "memory": "256Mi"},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "capabilities": {"drop": ["ALL"]},
        },
    }


def _volumes(metadata: dict[str, Any], settings: SidecarInjectorSettings) -> list[dict[str, Any]]:
    policy_configmap = (
        str((metadata.get("annotations") or {}).get(settings.policy_configmap_annotation_key, "") or "").strip()
        or settings.policy_configmap_name
    )
    volumes: list[dict[str, Any]] = [{"name": "agent-bom-audit-logs", "emptyDir": {}}]
    if policy_configmap:
        volumes.append({"name": "agent-bom-proxy-policy", "configMap": {"name": policy_configmap}})
    return volumes


def _build_patch(pod: dict[str, Any], settings: SidecarInjectorSettings) -> list[dict[str, Any]]:
    metadata = pod.setdefault("metadata", {})
    spec = pod.setdefault("spec", {})
    patches: list[dict[str, Any]] = []

    annotations = metadata.get("annotations")
    if annotations is None:
        patches.append(_patch_add("/metadata/annotations", {}))
        annotations = {}
    if settings.injected_annotation_key not in annotations:
        patches.append(_patch_add(f"/metadata/annotations/{settings.injected_annotation_key.replace('/', '~1')}", "true"))
    if "prometheus.io/scrape" not in annotations:
        patches.append(_patch_add("/metadata/annotations/prometheus.io~1scrape", "true"))
    if "prometheus.io/port" not in annotations:
        patches.append(_patch_add("/metadata/annotations/prometheus.io~1port", str(settings.metrics_port)))
    if "prometheus.io/path" not in annotations:
        patches.append(_patch_add("/metadata/annotations/prometheus.io~1path", "/metrics"))

    if spec.get("volumes") is None:
        patches.append(_patch_add("/spec/volumes", []))
    existing_volumes = {volume.get("name") for volume in (spec.get("volumes") or [])}
    for volume in _volumes(metadata, settings):
        if volume["name"] not in existing_volumes:
            patches.append(_patch_add("/spec/volumes/-", volume))

    if spec.get("containers") is None:
        patches.append(_patch_add("/spec/containers", []))
    patches.append(_patch_add("/spec/containers/-", _sidecar_container(settings, metadata)))
    return patches


def _audit_injection(review_request: dict[str, Any], metadata: dict[str, Any], settings: SidecarInjectorSettings, target_url: str) -> None:
    request_info = review_request.get("request") or {}
    namespace = request_info.get("namespace") or metadata.get("namespace") or "default"
    name = metadata.get("name") or metadata.get("generateName") or "generated"
    tenant_id = (
        (metadata.get("labels") or {}).get(settings.tenant_label_key)
        or (metadata.get("annotations") or {}).get(settings.tenant_label_key)
        or "default"
    )
    owner_refs = metadata.get("ownerReferences") or []
    workload_ref = owner_refs[0].get("name") if owner_refs else ""
    settings.audit_logger(
        "runtime.sidecar_injected",
        actor=settings.audit_actor,
        resource=f"k8s/pod/{namespace}/{name}",
        tenant_id=tenant_id,
        namespace=namespace,
        workload_ref=workload_ref or name,
        target_url=target_url,
        request_uid=request_info.get("uid", ""),
    )


def _review_response(uid: str, *, allowed: bool = True, patch: list[dict[str, Any]] | None = None) -> JSONResponse:
    review: dict[str, Any] = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {"uid": uid, "allowed": allowed},
    }
    if patch:
        patch_bytes = json.dumps(patch, separators=(",", ":")).encode("utf-8")
        review["response"]["patchType"] = "JSONPatch"
        review["response"]["patch"] = base64.b64encode(patch_bytes).decode("ascii")
    return JSONResponse(review)


def create_sidecar_injector_app(settings: SidecarInjectorSettings) -> FastAPI:
    app = FastAPI(title="agent-bom sidecar injector", version="1")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/mutate")
    async def mutate(review: dict[str, Any]) -> JSONResponse:
        request = review.get("request") or {}
        uid = str(request.get("uid") or "")
        if request.get("operation") != "CREATE":
            return _review_response(uid)
        if (request.get("kind") or {}).get("kind") != "Pod":
            return _review_response(uid)

        pod = request.get("object") or {}
        metadata = pod.get("metadata") or {}
        if not _should_inject(metadata, settings):
            return _review_response(uid)
        if _already_injected(pod, settings):
            return _review_response(uid)

        patch = _build_patch(pod, settings)
        _audit_injection(review, metadata, settings, _target_url(metadata, settings))
        return _review_response(uid, patch=patch)

    return app


__all__ = ["SidecarInjectorSettings", "create_sidecar_injector_app"]
