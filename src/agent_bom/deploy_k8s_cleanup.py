"""Best-effort namespace cleanup for Helm pre/post-delete hooks."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Literal

SERVICEACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SERVICEACCOUNT_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


@dataclass(frozen=True)
class CleanupOperation:
    kind: str
    target: Literal["collection", "named"]
    api_path: str
    name: str | None = None
    label_selector: str | None = None


def build_cleanup_operations(
    *,
    namespace: str,
    label_selector: str,
    target_secrets: list[str],
) -> list[CleanupOperation]:
    """Build the ordered cleanup operations for a release namespace."""

    operations = [
        CleanupOperation(
            kind="ExternalSecret",
            target="collection",
            api_path=f"/apis/external-secrets.io/v1beta1/namespaces/{namespace}/externalsecrets",
            label_selector=label_selector,
        ),
    ]
    operations.extend(
        CleanupOperation(
            kind="Secret",
            target="named",
            api_path=f"/api/v1/namespaces/{namespace}/secrets/{secret_name}",
            name=secret_name,
        )
        for secret_name in target_secrets
        if secret_name
    )
    operations.extend(
        [
            CleanupOperation(
                kind="CronJob",
                target="collection",
                api_path=f"/apis/batch/v1/namespaces/{namespace}/cronjobs",
                label_selector=label_selector,
            ),
            CleanupOperation(
                kind="Job",
                target="collection",
                api_path=f"/apis/batch/v1/namespaces/{namespace}/jobs",
                label_selector=label_selector,
            ),
            CleanupOperation(
                kind="PersistentVolumeClaim",
                target="collection",
                api_path=f"/api/v1/namespaces/{namespace}/persistentvolumeclaims",
                label_selector=label_selector,
            ),
        ]
    )
    return operations


def _incluster_api_server() -> str:
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS") or os.environ.get("KUBERNETES_SERVICE_PORT")
    if not host or not port:
        raise RuntimeError("KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT are required for in-cluster cleanup")
    return f"https://{host}:{port}"


def _read_serviceaccount_file(path: str) -> str:
    return open(path, encoding="utf-8").read().strip()


def _request(
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
) -> tuple[int, str]:
    server = _incluster_api_server()
    token = _read_serviceaccount_file(SERVICEACCOUNT_TOKEN_PATH)
    query_string = f"?{urllib.parse.urlencode(query)}" if query else ""
    request = urllib.request.Request(
        f"{server}{path}{query_string}",
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    ssl_context = ssl.create_default_context(cafile=SERVICEACCOUNT_CA_PATH)
    try:
        # This is restricted to the in-cluster Kubernetes API host and the
        # mounted service-account CA/token, not an operator-controlled URL.
        with urllib.request.urlopen(request, context=ssl_context, timeout=15) as response:  # nosec B310
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body


def execute_cleanup(operations: list[CleanupOperation]) -> int:
    """Execute best-effort cleanup operations and emit one line per result."""

    failed = 0
    for operation in operations:
        query = {"labelSelector": operation.label_selector} if operation.target == "collection" and operation.label_selector else None
        status, body = _request("DELETE", operation.api_path, query=query)
        if status in {200, 202, 404}:
            suffix = operation.name or operation.label_selector or ""
            sys.stdout.write(f"{operation.kind}: ok {suffix}\n")
            continue
        failed += 1
        detail = body
        try:
            payload = json.loads(body)
            detail = payload.get("message") or payload.get("details") or body
        except json.JSONDecodeError:
            pass
        suffix = operation.name or operation.label_selector or ""
        sys.stderr.write(f"{operation.kind}: failed {suffix} ({status}) {detail}\n")
    return failed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True, help="Namespace containing the Helm release")
    parser.add_argument("--label-selector", required=True, help="Label selector used for collection deletes")
    parser.add_argument(
        "--target-secret",
        dest="target_secrets",
        action="append",
        default=[],
        help="Generated Secret name to delete explicitly (repeatable)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    operations = build_cleanup_operations(
        namespace=args.namespace,
        label_selector=args.label_selector,
        target_secrets=args.target_secrets,
    )
    return 1 if execute_cleanup(operations) else 0


if __name__ == "__main__":
    raise SystemExit(main())
