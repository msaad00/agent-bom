"""Shared helpers for parsing deployment archives from serverless runtimes."""

from __future__ import annotations

import io
import logging
import zipfile
from typing import Any

from agent_bom.models import Package

logger = logging.getLogger(__name__)


def packages_from_zip_bytes(data: bytes, *, ecosystem: str) -> list[Package]:
    """Parse Python or Node packages from an in-memory deployment zip."""
    if not data:
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if ecosystem == "pypi":
                from agent_bom.cloud.aws import _parse_python_packages_from_zip

                return _parse_python_packages_from_zip(zf)
            if ecosystem == "npm":
                from agent_bom.cloud.aws import _parse_node_packages_from_zip

                return _parse_node_packages_from_zip(zf)
    except Exception as exc:  # noqa: BLE001 — malformed archives degrade to empty
        logger.debug("Could not parse serverless zip (%s): %s", ecosystem, exc)
    return []


def ecosystem_from_runtime(runtime: str) -> str | None:
    """Map a cloud runtime string to ``pypi`` or ``npm`` when parseable."""
    lowered = runtime.lower()
    if "python" in lowered:
        return "pypi"
    if "node" in lowered:
        return "npm"
    return None


def extract_gcp_storage_source_packages(
    bucket: str,
    obj: str,
    runtime: str,
    warnings: list[str],
) -> list[Package]:
    """Download a Cloud Functions / Cloud Run source archive from GCS and parse deps."""
    eco = ecosystem_from_runtime(runtime)
    if not eco or not bucket or not obj:
        return []
    try:
        from google.cloud import storage
    except ImportError:
        warnings.append("google-cloud-storage not installed; skipping GCS source archive parse.")
        return []
    try:
        client = storage.Client()
        data = client.bucket(bucket).blob(obj).download_as_bytes()
        return packages_from_zip_bytes(data, ecosystem=eco)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not parse GCS source gs://{bucket}/{obj}: {exc}")
        return []


def extract_azure_function_packages(
    web_client: Any,
    rg_name: str,
    app_name: str,
    runtime_stack: str,
    warnings: list[str],
) -> list[Package]:
    """Fetch the deployed wwwroot zip via Kudu and parse Python/Node dependencies."""
    eco = ecosystem_from_runtime(runtime_stack)
    if not eco or not rg_name or not app_name:
        return []
    list_credentials = getattr(web_client.web_apps, "list_publishing_credentials", None)
    if not callable(list_credentials):
        return []
    try:
        creds = list_credentials(rg_name, app_name)
        props = getattr(creds, "properties", creds)
        scm_uri = str(getattr(props, "scm_uri", "") or "").rstrip("/")
        username = str(getattr(props, "publishing_user_name", "") or "")
        password = str(getattr(props, "publishing_password", "") or "")
        if not scm_uri or not username or not password:
            warnings.append(f"Azure Function {app_name}: publishing credentials unavailable for zip fetch.")
            return []
        zip_url = f"{scm_uri}/api/zip/site/wwwroot/"
        import base64

        from agent_bom.http_client import fetch_bytes

        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        data = fetch_bytes(zip_url, timeout=60, headers={"Authorization": f"Basic {token}"})
        return packages_from_zip_bytes(data, ecosystem=eco)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not parse Azure Function deployment zip for {app_name}: {exc}")
        return []
